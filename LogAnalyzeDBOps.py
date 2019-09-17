from pymongo import MongoClient
import bson
import datetime

def demo(Id):
    con = MongoClient("mongodb://localhost:27017/")
    db = con["logs"]
    tableLogStore = db["log_store"]
    data = list(
        tableLogStore.find({'Id': Id}).limit(1)
    )
    return data

def getAllLogs(storeName): # 7556 all log count, Store: "wintest"
    con = MongoClient("mongodb://localhost:27017/")
    db = con["logs"]
    tableLogStore = db["log_store"]
    data = list(
        tableLogStore.find({'Store': storeName}).sort('TimeCreated', 1)
    )
    return data
    


def getUniqueStoreName():
    con = MongoClient("mongodb://localhost:27017/")
    db = con["logs"]
    tableLogStore = db["log_store"]
    storeNames = list(tableLogStore.distinct('Store'))
    storeNames = [''] + storeNames
    con.close()
    return storeNames

def getLogDate(storeName):
    con = MongoClient("mongodb://localhost:27017/")
    db = con["logs"]
    tableLogStore = db["log_store"]
    cur = tableLogStore.find({'Store': storeName}).sort('TimeCreated', 1)
    con.close()
    return cur

def getLogDataUsingQuery(storeName, field, values):
    con = MongoClient("mongodb://localhost:27017/")
    db = con["logs"]
    print(storeName, field, values)
    tableLogStore = db["log_store"]
    cur = tableLogStore.find({
        'Store': str(storeName),
        field : {'$in': values}
    }).sort('TimeCreated', 1)
    return list(cur)

# Checks for complete session status
def checkCompleteSessionStatus(storeName, sesId):
    sesIds = sesId[0] + '|' + sesId[1]
    con = MongoClient("mongodb://localhost:27017/")
    db = con["logs"]
    tableLogStore = db["log_store"]
    data = list(tableLogStore.find({'Store': storeName, 'Id': {'$in': [4624, 4647]}, 'Message': {'$regex': sesIds}}).sort('TimeCreated', 1))
    if data[0]['Id'] == "4624" and data[1]['Id'] == "4647":
        return True
    return False

def getLogsForAnalyze(storeName, sesId, eventIds):
    con = MongoClient("mongodb://localhost:27017/")
    db = con["logs"]
    tableLogStore = db["log_store"]
    cur = list(tableLogStore.find({
        'Store': storeName,
        'Id': {'$in': ["4624", "4647"]},
        'Message': {'$regex': sesId}
    }).sort('TimeCreated', 1))

    startDateTime = cur[0]['TimeCreated']
    endDateTime = cur[-1]['TimeCreated']

    cur = list(tableLogStore.find({
        'Store': storeName,
        'Id': {'$in': eventIds},
        'TimeCreated': {'$gte': startDateTime, '$lte': endDateTime}
    }).sort('TimeCreated', 1))

    return cur


def insertReport(log, status, reportId, reportMsg, forensic):
    con = MongoClient("mongodb://localhost:27017/")
    db = con["logs"]
    tableLogStore = db["log_analyze_report"]

    cur = tableLogStore.insert_one({
        'log_id': log['_id'],
        'attack_status': status,
        'report_Id': reportId,
        'report_msg': reportMsg,
        'Message': log['Message'],
        'Id': log['Id'],
        'Version': log['Version'],
        'Qualifiers': log['Qualifiers'],
        'Level': log['Level'],
        'Task': log['Task'],
        'Opcode': log['Opcode'],
        'Keywords': log['Keywords'],
        'RecordId': log['RecordId'],
        'ProviderName': log['ProviderName'],
        'ProviderId': log['ProviderId'],
        'LogName': log['LogName'],
        'ProcessId': log['ProcessId'],
        'ThreadId': log['ThreadId'],
        'MachineName': log['MachineName'],
        'UserId': log['UserId'],
        'TimeCreated': log['TimeCreated'],
        'ActivityId': log['ActivityId'],
        'RelatedActivityId': log['RelatedActivityId'],
        'ContainerLog': log['ContainerLog'],
        'MatchedQueryIds': log['MatchedQueryIds'],
        'Bookmark': log['Bookmark'],
        'LevelDisplayName': log['LevelDisplayName'],
        'OpcodeDisplayName': log['OpcodeDisplayName'],
        'TaskDisplayName': log['TaskDisplayName'],
        'KeywordsDisplayNames': log['KeywordsDisplayNames'],
        'Properties': log['Properties'],
        'Store': log['Store'],
        'who': forensic['who'],
        'fromwhere': forensic['fromwhere'],
        'when': forensic['when'],
        'what': forensic['what'],
        'how': forensic['how'],
        'why': forensic['why']
    })
    return cur


def getKnownLogIds(reportId):
    con = MongoClient("mongodb://localhost:27017/")
    db = con["logs"]
    tableLogStore = db["log_analyze_report"]
    cur = tableLogStore.find({'report_Id': reportId})
    logIds = []
    for c in cur:
        if c['log_id'] not in logIds:
            logIds.append(c['log_id'])

    return logIds

def getFailedObjectAccessLogs(storeName):
    con = MongoClient("mongodb://localhost:27017/")
    db = con["logs"]
    tableLogStore = db["log_store"]
    cur = tableLogStore.find({'Store': storeName, "Id": "4656", "Keywords": bson.int64.Int64(-9218868437227405312)}).sort('TimeCreated', -1)
    return list(cur)


def getSuccessObjectAccessLogs(storeName):
    con = MongoClient("mongodb://localhost:27017/")
    db = con["logs"]
    tableLogStore = db["log_store"]
    cur = tableLogStore.find({'Store': storeName, "Id": "4656", "Keywords": bson.int64.Int64(-9214364837600034816)}).sort('TimeCreated', -1)
    return list(cur)


def getPrintLogs(storeName):
    con = MongoClient("mongodb://localhost:27017/")
    db = con["logs"]
    tableLogStore = db["log_store"]
    cur = tableLogStore.find({'Store': storeName, "Id": "307"}).sort('TimeCreated', -1)
    return list(cur)

# def DEMO():
#     con = MongoClient("mongodb://localhost:27017/")
#     db = con["logs"]
#     tableLogStore = db["log_store"]
#     storeName = 'wintest'
#     field = 'Id'
#     values = ['1102']
#     cur = tableLogStore.find({
#         'Store': str(storeName),
#         field : {'$in': values}
#     }).sort('TimeCreated', 1)
#     logonIDs = []
#     for c in cur:
#         print(list(c))


# if __name__ == '__main__':
#     DEMO()
#     res = (getPrintLogs('home-log-01'))
#     for r in res:
#         print(r['Message'])
    # print(getFailedAccessLogs('home-log', getKnownLogIds('home-log_2019-08-07_16:45:59.625541_0x1E6C1F95')))





# if __name__ == '__main__':
#     res = getKnownLogIds('home-log_2019-08-07_16:45:59.625541_0x1E6C1F95')
#     for r in res:
#         print(r)
    # l = ['0x14DE10F', '0x14DDE15', '0x14E6553', '0x3E7', '0x1514F1B', '0x1514EFD', '0x15FC218', '0x15FC1F8', '0x16DFFB6', '0x16DFF94', '0x1719ABB', '0x1719A9F', '0x171D5B1', '0x171D591', '0x18A5056', '0x18A5025', '0x18ABAD9', '0x18ABABC']
    # for i in l:
    #     if checkCompleteSessionStatus('win-acc-1', i):
    #         print(i)
    # res = getLogsForAnalyze('win-acc-1', '0x14DE10F', [4624, 4656, 4663, 4647])
    # for i in res:
    #     print(i['Message'][:i['Message'].index('\n')])









