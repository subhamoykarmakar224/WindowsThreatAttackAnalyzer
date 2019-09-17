from pymongo import MongoClient
import datetime


def getUniqueReports():
    con = MongoClient("mongodb://localhost:27017/")
    db = con["logs"]
    tableLogStore = db["log_analyze_report"]
    reportsList = list(tableLogStore.distinct('report_Id'))
    reportsList = [''] + reportsList
    con.close()
    return reportsList

def getReportCounts(reportId):
    con = MongoClient("mongodb://localhost:27017/")
    db = con["logs"]
    tableLogStore = db["log_analyze_report"]
    genCount = tableLogStore.find({'report_Id': reportId, 'attack_status': 0}).count()
    suspCount = tableLogStore.find({'report_Id': reportId, 'attack_status': 1}).count()
    threatCount = tableLogStore.find({'report_Id': reportId, 'attack_status': 2}).count()
    attackCount = tableLogStore.find({'report_Id': reportId, 'attack_status': 3}).count()

    con.close()
    return [genCount, suspCount, threatCount, attackCount]

# if __name__ == '__main__':
#     print(getUniqueReports())