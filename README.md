## This script is intended as a demonstration of functionality. Do not assume it is production worthy.

Use cribl_lookupdate to automate lookup file updates. You can either upload a whole new file, or just append a new row. It should work with either self-managed or Cloud Leaders.

## Requirements:
* you must have [Cribl python-api-wrapper](https://github.com/criblio/python-api-wrapper/) installed

There is a help message if you run with no args.

Sample run to append a new row consisting of 1, 2 to the existing lookup file test.csv in the Worker Group Lab:
```
$ python3 cribl_lookupdate.py -l https://main-<your-instance>.cribl.cloud/api/v1 -u <apiuserkey> -P <apiusersecret> -g Lab -f test.csv -a '1,2'
bueno
```

Sample run same as above, but upload the local file test.csv to *replace* test.csv on the leader (leave off the -a args):
```
$ python3 cribl_lookupdate.py -l https://main-<your-instance>.cribl.cloud/api/v1 -u <apiuserkey> -P <apiusersecret> -g Lab -f test.csv'
bueno
```

If you have an environment variable named CRIBL_AUTH_TOKEN the script will use that instead of authenticating with a userid and password.

