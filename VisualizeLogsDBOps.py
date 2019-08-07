from pymongo import MongoClient
import datetime


def getUniqueReportNames():
    con = MongoClient("mongodb://localhost:27017/")
    db = con["logs"]
    tableLogStore = db["log_analyze_report"]
    storeNames = list(tableLogStore.distinct('report_Id'))
    storeNames = [''] + storeNames
    con.close()
    return storeNames

def getFullReport(reportId):
    con = MongoClient("mongodb://localhost:27017/")
    db = con["logs"]
    tableLogStore = db["log_analyze_report"]
    reports = list(tableLogStore.find({'report_Id': reportId}))
    con.close()
    return reports
