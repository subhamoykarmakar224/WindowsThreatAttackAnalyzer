import pandas as pd
import re
import csv
import pymongo
import bson
import datetime as dt
#import analyst
import numpy as np

def windowsLogParse(path, store):
    #path = str(path).replace('/', '\\\\')
    # store = 'win-acc-1'
    myclient = pymongo.MongoClient("mongodb://localhost:27017/")
    mydb = myclient["logs"]
    mycol = mydb["log_store"]
    f = open(path)
    '''l = f.readlines()
    fields = []
    for i in range(0,1):
        fields = l[i].split(',')'''

    line = pd.read_csv(f,sep=',',skiprows = 1)
    count = mycol.count() + 1

    # print(line.iloc[2]['Properties'])
    for i in range(0,len(line)):
        # try:
        #     time_sec = dt.datetime.strptime(line.iloc[i]['TimeCreated'], "%d-%m-%Y %H:%M").strftime("%s")
        #     time_mili = int(float(time_sec)*1000)
        # except:
        #     time_sec = dt.datetime.strptime(line.iloc[i]['TimeCreated'], "%d-%m-%Y %H:%M:%S").strftime("%s")
        #     time_mili = int(float(time_sec)*1000)
        mycol.insert_one({
            '_id' : i+count,
            'Message' : line.iloc[i]['Message'],
            'Id' : line.iloc[i]['Id'],
            'Version' : line.iloc[i]['Version'],
            'Qualifiers' : line.iloc[i]['Qualifiers'],
            'Level' : line.iloc[i]['Level'],
            'Task' : line.iloc[i]['Task'],
            'Opcode' : line.iloc[i]['Opcode'],
            'Keywords' : line.iloc[i]['Keywords'],
            'RecordId' : line.iloc[i]['RecordId'],
            'ProviderName' : line.iloc[i]['ProviderName'],
            'ProviderId' : line.iloc[i]['ProviderId'],
            'LogName' : line.iloc[i]['LogName'],
            'ProcessId' : line.iloc[i]['ProcessId'],
            'ThreadId' : line.iloc[i]['ThreadId'],
            'MachineName' : line.iloc[i]['MachineName'],
            'UserId' : line.iloc[i]['UserId'],
            'TimeCreated' : dt.datetime.strptime(line.iloc[i]['TimeCreated'], "%d-%m-%Y %H:%M:%S"),
            # 'DateTime':'',
            'ActivityId' : line.iloc[i]['ActivityId'],
            'RelatedActivityId' : line.iloc[i]['RelatedActivityId'],
            'ContainerLog' : line.iloc[i]['ContainerLog'],
            'MatchedQueryIds' : line.iloc[i]['MatchedQueryIds'],
            'Bookmark' : line.iloc[i]['Bookmark'],
            'LevelDisplayName' : line.iloc[i]['LevelDisplayName'],
            'OpcodeDisplayName' : line.iloc[i]['OpcodeDisplayName'],
            'TaskDisplayName' : line.iloc[i]['TaskDisplayName'],
            'KeywordsDisplayNames' : line.iloc[i]['KeywordsDisplayNames'],
            'Properties' : line.iloc[i]['Properties'],
            'Store' : str(store)
        })
