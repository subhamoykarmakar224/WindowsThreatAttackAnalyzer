import pandas as pd
import re
import csv
import pymongo
import datetime as dt
import dateutil
#import analyst
import numpy as np

def windowsLogParse(path, store):
    #path = str(path).replace('/', '\\\\')
#   store = 'win-acc-1'
    myclient = pymongo.MongoClient("mongodb://localhost:27017/")
    mydb = myclient["logs"]
    mycol = mydb["log_store"]
    f = open(path, 'r')

    line = pd.read_csv(f, sep=',', skiprows = 1)
    count = mycol.count() + 1
    data = []
    # print(line.iloc[2]['Properties'])
    for i in range(0,len(line)):
        # print(dt.datetime.strptime(line.iloc[i]['TimeCreated'], "%d-%m-%Y %I:%M:%S"))
        try:
            date_time = dt.datetime.strptime(line.iloc[i]['TimeCreated'], "%d-%m-%Y %H:%M:%S")
            # time_mili = int(float(time_sec)*1000)
        except:
            # date_time = dt.datetime.strptime(line.iloc[i]['TimeCreated'], "%d/%m/%Y %I:%M:%S %p")
            try:
                date_time = dt.datetime.strptime(line.iloc[i]['TimeCreated'], "%d/%b/%Y %H:%M:%S")
            # time_mili = int(float(time_sec)*1000)
            except: # "%d/%b/%Y %H:%M:%S"
                date_time = dt.datetime.strptime(line.iloc[i]['TimeCreated'], "%d/%m/%Y %I:%M:%S %p")

        # data.append({
        mycol.insert_one({
            '_id' : str(i+count),
            'Message' : str(line.iloc[i]['Message']),
            'Id' : str(line.iloc[i]['Id']),
            'Version' : str(line.iloc[i]['Version']),
            'Qualifiers' : str(line.iloc[i]['Qualifiers']),
            'Level' : str(line.iloc[i]['Level']),
            'Task' : str(line.iloc[i]['Task']),
            'Opcode' : str(line.iloc[i]['Opcode']),
            'Keywords' : str(line.iloc[i]['Keywords']),
            'RecordId' : str(line.iloc[i]['RecordId']),
            'ProviderName' : str(line.iloc[i]['ProviderName']),
            'ProviderId' : str(line.iloc[i]['ProviderId']),
            'LogName' : str(line.iloc[i]['LogName']),
            'ProcessId' : str(line.iloc[i]['ProcessId']),
            'ThreadId' : str(line.iloc[i]['ThreadId']),
            'MachineName' : str(line.iloc[i]['MachineName']),
            'UserId' : str(line.iloc[i]['UserId']),
            'TimeCreated' : date_time,
            'ActivityId' : str(line.iloc[i]['ActivityId']),
            'RelatedActivityId' : str(line.iloc[i]['RelatedActivityId']),
            'ContainerLog' : str(line.iloc[i]['ContainerLog']),
            'MatchedQueryIds' : str(line.iloc[i]['MatchedQueryIds']),
            'Bookmark' : str(line.iloc[i]['Bookmark']),
            'LevelDisplayName' : str(line.iloc[i]['LevelDisplayName']),
            'OpcodeDisplayName' : str(line.iloc[i]['OpcodeDisplayName']),
            'TaskDisplayName' : str(line.iloc[i]['TaskDisplayName']),
            'KeywordsDisplayNames' : str(line.iloc[i]['KeywordsDisplayNames']),
            'Properties' : str(line.iloc[i]['Properties']),
            'Store' : "wintest"
        })
    
    # mycol.insert_many(data)


if __name__ == "__main__":
    path = 'logs\session-log-1\step14.csv'
    store = 'test'
    windowsLogParse(path, store)