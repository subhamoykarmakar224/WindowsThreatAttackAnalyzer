import pymongo
import datetime as dt

def windowsLogParse():
    myclient = pymongo.MongoClient("mongodb://localhost:27017/")
    mydb = myclient["logs"]
    mycol = mydb["log_store"]
    cur = mycol.find(
        {'Store': 'win-acc-1',
         # 'Id': {'$in': [4656]},
         # 'TimeCreated': {
             # '$gte': dt.datetime(2019, 06, 26, 21, 6, 55),
             # '$lte': dt.datetime(2019, 06, 26, 21, 41, 07)
        # }
    }).sort('TimeCreated', 1)
    logs = list(cur)
    for i in range(0, len(logs)-1):
        if logs[i]['Id'] == '4656' and logs[i+1]['Id'] != '4656':
            print(logs[i+1]['Id'])


if __name__ == '__main__':
    windowsLogParse()