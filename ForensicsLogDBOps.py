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

def getReports(report_Id):
    con = MongoClient("mongodb://localhost:27017/")
    db = con["logs"]
    tableLogStore = db["log_analyze_report"]
    # reportsList = tableLogStore.find({'report_Id' : report_Id, "attack_status": 3})
    reportsList = tableLogStore.find({'report_Id' : report_Id})
    con.close()
    return list(reportsList)