#!/usr/bin/python

import requests
import json
import os
import sys
import argparse
import getpass
from cribl_python_api_wrapper.inputs import *
from cribl_python_api_wrapper.versioning import *
from cribl_python_api_wrapper.auth import *
from cribl_python_api_wrapper.lookups import *
from cribl_python_api_wrapper.groups import *

#############################
# I don't care about insecure certs
# (maybe you do, comment out if so)
requests.urllib3.disable_warnings(requests.urllib3.exceptions.InsecureRequestWarning)

#############################
# where we login to get a bearer token
auth_uri = '/api/v1/auth/login'
cloud_token_url = 'https://login.cribl.cloud/oauth/token'

#############################
# prompt for password if one is not supplied
class Password:
    # if password is provided, use it. otherwise prompt
    DEFAULT = 'Prompt if not specified'

    def __init__(self, value):
        if value == self.DEFAULT:
            value = getpass.getpass('Password: ')
        self.value = value

    def __str__(self):
        return self.value

# Check if the TOKEN environment variable exists
def get_token_from_env():
    return os.getenv('CRIBL_AUTH_TOKEN')
    
#############################
# parse the command args
def parse_args():
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-D', '--debug', help='Extra output',action='store_true')
    parser.add_argument('-l', '--leader', help='Leader URL, http(s)://leader:port',required=True)
    parser.add_argument('-g', '--group', type=str, help="Target worker group", required=True)
    parser.add_argument('-f', '--filepath', type=str, help="Path to the file we want to upload", required=True)
    parser.add_argument('-a', '--appenddata', type=str, help="Data to append to the existing lookup", required=False)  
    parser.add_argument('-u', '--username', help='API token id (cloud) or user id (self-managed)',required=False)
    
    bearer_token = get_token_from_env()
    parser.add_argument('-P', '--password', type=Password, help='Specify password or secret, or get prompted for it',
                        default=Password.DEFAULT if not bearer_token else bearer_token)

    args = parser.parse_args()
    return args

# some debug notes
def debug_log(log_str):
    if args.debug:
        print("DEBUG: {}".format(log_str))

#############################
# get logged in for Cribl SaaS
def cloud_auth(client_id,client_secret):
    # get logged in and grab a token
    header = {'accept': 'application/json', 'Content-Type': 'application/json'}
    login = '{"grant_type": "client_credentials","client_id": "' + client_id + '", "client_secret": "' + client_secret + '","audience":"https://api.cribl.cloud"}'
    r = requests.post(cloud_token_url,headers=header,data=login,verify=False)
    if (r.status_code == 200):
        res = r.json()
        debug_log("Bearer token: " + res["access_token"])
        return res["access_token"]
    else:
        print("Login failed, terminating")
        print(str(r.json()))
        sys.exit()

#############################
# append to a new file
def append_row(leader, group, auth_token, lookup_id, new_data):
    url = leader + "/m/<WG>/system/lookups".replace("<WG>",group) + "/" + lookup_id + "/content"
    headers = {"Authorization": "Bearer {}".format(auth_token), "accept": "application/json", "Content-Type": "application/json"}
    file_info = requests.get(url,headers=headers)
    row_count = file_info.json()['count']
    debug_log("append: lookup {} has rowcount {}".format(lookup_id, row_count))
    new_row = [{"op":"add","rowId":row_count + 1,"value":new_data.split(',')}]
    debug_log("append: payload {}".format(new_row))
    append_resp = requests.patch(url,headers=headers,json=new_row)
    debug_log(append_resp.json())
    if append_resp.status_code == 200:
        return(append_resp.json())
    else:
        print("APPEND action failed with status {}\nexiting".format(append_resp.status_code))
        sys.exit(1)
             
#############################
# upload a new file
def upload_file(leader, group, auth_token, file_path):
    resp = upload_lookup_file(leader,auth_token,file_path,group)
    print(resp.json())
    if resp.status_code == 200:
        return(resp.json())
    else:
        print("PUT upload failed with returned status {}\nexiting!".format(r.status_code))
        sys.exit(1)

#############################
# move the file into place on the Leader
# current library doesn't have this method, so we'll gen it up here
def install_file(leader, group, auth_token, dest_file, uploaded_file):
    # We don't want the whole path, just the file name
    dest_file = dest_file.split('/')[-1]
    content = {'id': dest_file, 'fileInfo': {'filename':uploaded_file}}
    headers = {"Authorization": "Bearer {}".format(auth_token), "accept": "application/json", "Content-Type": "application/json"}
    url = leader + "/m/<WG>/system/lookups".replace("<WG>",group) + "/" + dest_file
    debug_log("sending PATCH to {} with headers:{} and data:{}".format(url,headers,json.dumps(content)))
    resp = requests.patch(url,headers=headers,json=content)
    
    if (resp.status_code == 200):
        debug_log("Patch: OK New file in place:")
        return(resp)
    else:
        print("PATCH failed with returned status {}\nexiting!".format(resp))
        sys.exit(1)

#############################
# commit the change
def commit(leader, group, auth_token, file_path, msg):
    lookup_id = file_path.split('/')[-1]
    path_csv = "groups/" + group + "/data/lookups/" + lookup_id
    path_yml = path_csv.replace('.csv','.yml')
    data = {'message': msg, 'group': args.group, 'files': [path_csv,path_yml]}
    debug_log("create_commit with data: {}".format(json.dumps(data)))
    resp = create_commit(leader,auth_token,data)

    if (resp.status_code == 200):
        return(resp)
    else:
        print("create_commit failed with returned status {}\nexiting!".format(r.status_code))
        print("details:\nurl: {}\nheaders: {}\ndata: {}\n".format(url,header,json.dumps(data)))
        sys.exit(1)


#############################
#############################
# main 
if __name__ == "__main__":
    args = parse_args()
    # get logged in if needed
    if os.getenv('CRIBL_AUTH_TOKEN'):
        # use bearer token in the env if it's there
        bearer_token = os.getenv('CRIBL_AUTH_TOKEN')
    else:
        # use cloud login if it looks like a cloud url
        if args.leader.find('cribl.cloud') > 0:
            bearer_token = cloud_auth(args.username,str(args.password))
        # for self-managed use the library's built-in method
        else:
            bearer_token = api_get_auth_data(args.leader, args.username, args.password).json()["token"]
    
    if "appenddata" in args and args.appenddata != None:
        debug_log("appending data only")
        append_row(args.leader, args.group, bearer_token, args.filepath, args.appenddata)

    else:
        # Upload the file
        debug_log("sending file to upload endpoint")
        upload_results = upload_file(args.leader, args.group, bearer_token, args.filepath)
        debug_log(upload_results)
        # move the uploaded file into place
        if "filename" in upload_results:
            install_results = install_file(args.leader, args.group, bearer_token, args.filepath, upload_results["filename"])

    # commit the changes
    debug_log("commit the changes")
    commit_resp = commit(args.leader, args.group, bearer_token, args.filepath,"automation: updated lookup file")
    debug_log(commit_resp.json())
    commit_id = commit_resp.json()['items'][0]['commit']
    if commit_id == '':
        print("file uploaded was unchanged from previous")
        sys.exit(0)
    debug_log("commit ID: " + commit_id)
    
    # deploy
    debug_log("deploy the changes from commitID:{} to group:{}".format(commit_id,args.group))
    deploy_results = deploy_commit(base_url=args.leader, cribl_auth_token=bearer_token, version=commit_id, worker_group=args.group)
    debug_log("Deploy results:{}".format(deploy_results))
    
    if deploy_results.status_code == 200:
        print("bueno")
    else:
        print("something happened at the deploy stage, status code: {}\n{}".format(deploy_results.status_code,deploy_results.text))
    
