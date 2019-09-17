import threading
import re
import datetime
import LogAnalyzeDBOps as db
import Messages as MSG
import datetime


logonID = '0x785E60E' # Admin actions
linkedLogonID = '0x78B8C4B' # Other actions

# logonID = '0x78B8C68' # Admin actions
# linkedLogonID = '0x78B8C4B' # Other actions
# logonID = '0x1E6C1F95' # Admin actions
# logonID = '0x7E94155' # Admin actions
# linkedLogonID = '0x1E6C1FFB' # Other actions


def analyzeLogs(storeName):
    reportId = storeName + '_' + str(datetime.datetime.now()).replace(' ', '_') + '_' + str(logonID)
    print('Start...')
    print('1...')
    getPolicyChangeEventStatus(storeName, reportId)
    print('2...')
    getWrongAccountPassword(storeName, reportId)
    print('3...')
    getAddAccountEventStatus(storeName, reportId)
    print('4...')
    getDelAccountEventStatus(storeName, reportId)
    print('5...')
    getEventLogsDeleteEvent(storeName, reportId)
    print('6...')
    getTryRunWithoutAccess(storeName, reportId)
    print('7...')
    fillInTheUnknowLogs(storeName, reportId)
    print('8...')
    getPrintDate(storeName, reportId)
    print('Done...')


def getForensicData(logData, whatData, howEventIdSeq, whyStmt):
    # print(logData)
    forensics = {
        'who': '',
        'fromwhere': '',
        'when': '',
        'what': whatData,
        'how': howEventIdSeq,
        'why': whyStmt
    }
    if logData == -1: return forensics

    forensics['when'] = logData['TimeCreated']

    # who
    if logData['Message'].__contains__('New Logon'):
        tmpNewLogOnData = str(logData['Message'])
        tmpNewLogOnData = tmpNewLogOnData[tmpNewLogOnData.index('New Logon'):]
        tmpNewLogOnDataSID = tmpNewLogOnData[tmpNewLogOnData.index('Security ID'):tmpNewLogOnData.index('\n', tmpNewLogOnData.index('Security ID'))]
        tmpNewLogOnDataName = tmpNewLogOnData[tmpNewLogOnData.index('Account Name'):tmpNewLogOnData.index('\n', tmpNewLogOnData.index('Account Name'))]
        tmpNewLogOnDataName = tmpNewLogOnDataName.replace('\t', '').replace('\n', '').replace('\r', '')
        tmpNewLogOnDataSID = tmpNewLogOnDataSID.replace('\t', '').replace('\n', '').replace('\r', '')
        forensics['who'] = tmpNewLogOnDataName + ' (' + tmpNewLogOnDataSID + ')'
    else:
        try:
            tmpNewLogOnData = str(logData['Message'])
            tmpNewLogOnData = tmpNewLogOnData[tmpNewLogOnData.index('Subject'):]
            tmpNewLogOnDataSID = tmpNewLogOnData[tmpNewLogOnData.index('Security ID'):tmpNewLogOnData.index('\n', tmpNewLogOnData.index('Security ID'))]
            tmpNewLogOnDataName = tmpNewLogOnData[tmpNewLogOnData.index('Account Name'):tmpNewLogOnData.index('\n', tmpNewLogOnData.index('Account Name'))]
            tmpNewLogOnDataName = tmpNewLogOnDataName.replace('\t', '').replace('\n', '').replace('\r', '')
            tmpNewLogOnDataSID = tmpNewLogOnDataSID.replace('\t', '').replace('\n', '').replace('\r', '')
            forensics['who'] = tmpNewLogOnDataName + ' (' + tmpNewLogOnDataSID + ')'
        except:
            try:
                tmpNewLogOnData = str(logData['Message'])
                tmpNewLogOnData = tmpNewLogOnData[tmpNewLogOnData.index('Logon Account'):]
                tmpNewLogOnDataSID = tmpNewLogOnData[tmpNewLogOnData.index('Logon Account'):tmpNewLogOnData.index('\n', tmpNewLogOnData.index('Logon Account'))]
                tmpNewLogOnDataSID = tmpNewLogOnDataSID.replace('\t', '').replace('\n', '').replace('\r', '')
                forensics['who'] = tmpNewLogOnDataSID            
            except: #  Print Document owned by
                tmpNewLogOnData = str(logData['Message'])
                tmpNewLogOnData = tmpNewLogOnData[tmpNewLogOnData.index('Print Document owned by') + len('Print Document owned by'):].strip(' ')
                userName = tmpNewLogOnData.split(' ')[0]
                forensics['who'] = userName
    
    # fromwhere
    if logData['Message'].__contains__('Network Information'):
        tmpNewLogOnData = str(logData['Message'])
        tmpNewLogOnData = tmpNewLogOnData[tmpNewLogOnData.index('Network Information'):]
        tmpNewLogOnDataSID = tmpNewLogOnData[tmpNewLogOnData.index('Network Address'):tmpNewLogOnData.index('\n', tmpNewLogOnData.index('Network Address'))]
        tmpNewLogOnDataName = tmpNewLogOnData[tmpNewLogOnData.index('Port'):tmpNewLogOnData.index('\n', tmpNewLogOnData.index('Port'))]
        tmpNewLogOnDataName = tmpNewLogOnDataName.replace('\t', '').replace('\n', '').replace('\r', '')
        tmpNewLogOnDataSID = tmpNewLogOnDataSID.replace('\t', '').replace('\n', '').replace('\r', '')
        forensics['fromwhere'] = tmpNewLogOnDataSID + ' :' + tmpNewLogOnDataName
    elif logData['Message'].__contains__('Print Document owned by'): # Class Driver through port 192.168.0.19
        tmpNewLogOnData = str(logData['Message'])
        tmpNewLogOnData = tmpNewLogOnData[tmpNewLogOnData.index('Class Driver through port') + len('Class Driver through port'):].strip(' ').strip('.')
        ip = tmpNewLogOnData.split(' ')[0]
        forensics['fromwhere'] = ip
    else:
        forensics['fromwhere'] = 'localhost'

    # for k in forensics:
    #     print(k, forensics[k])

    return forensics

# When someone changes audit policy
def getPolicyChangeEventStatus(storeName, reportId):
    res = db.getLogDataUsingQuery(storeName, 'Id', ["4719"])
    for i in range(0, len(res)):
        msg = res[i]['Message']
        if msg.__contains__(logonID) or msg.__contains__(linkedLogonID): # insertReport(log, status, reportId, reportMsg)
            accMsg = msg
            accMsg = accMsg[accMsg.index('Account Name') + len('Account Name:'):accMsg.index('Account Domain')].replace('\t', '')
            accMsg = accMsg[:len(accMsg)-2]
            msg = msg[msg.index('Category'):].replace('\t', '')
            db.insertReport(
                res[i], 
                MSG.STATUS_SUSPICIOUS,
                reportId, 
                (MSG.SUSP_POLICY_CHANGE % accMsg) + '\n' + str(msg), 
                getForensicData(res[i], "Policy Change", "4719", "Integrity Breach")
                )


# When someone is getting the account password wrong
def getWrongAccountPassword(storeName, reportId):
    cnt = 0
    res = db.getLogDataUsingQuery(storeName, 'Id', ["4776", "4625"])
    userName = {}
    for i in range(0, len(res) - 1):
        if res[i]['Id'] == "4776" and res[i+1]['Id'] == "4625":
        # if res[i]['Id'] == 4625:
            # cnt += 1
            msg = res[i + 1]['Message']
            msg = msg[msg.index('Account For Which Logon Failed'):msg.index('Failure Information:') - 3]
            msg = msg.replace('\t', '').replace('\r', '')
            msg = msg[msg.index('Account Name:') + len('Account Name:'):msg.index('\n', msg.index('Account Name:'))]
            if msg not in userName.keys():
                userName[msg] = 1
            else:
                userName[msg] = userName[msg] + 1

    for usr in userName.keys():
        if userName[usr] > 2:
            for i in range(0, len(res)):
                # if res[i]['Id'] == 4776 and res[i + 1]['Id'] == 4625 and res[i]['Message'].__contains__(usr) and res[i+1]['Message'].__contains__(usr):
                if res[i]['Message'].__contains__(usr):
                    if res[i]['Id'] == "4625":
                        msg = res[i]['Message']
                        msg = msg[msg.index('Account For Which Logon Failed'):msg.index('Failure Information:') - 3]
                        msg = msg.replace('\t', '').replace('\r', '')
                        db.insertReport(
                            res[i], 
                            MSG.STATUS_THREAT, 
                            reportId, 
                            (MSG.THRT_WRONG_PASSWD_LOGIN) + '\n' + str(msg), 
                            getForensicData(res[i], "Logon Failure", "4776;4625", "Breach of Availability.")
                            )
                    else:
                        db.insertReport(res[i], MSG.STATUS_THREAT, reportId, (MSG.THRT_WRONG_PASSWD_LOGIN) + '\n' + str(res[i]['Message']), getForensicData(res[i], "Logon Failure", "4776;4625", "Breach of Availability."))
        else:
            i = 0
            for i in range(0, len(res)):
                # if res[i]['Id'] == 4776 and res[i + 1]['Id'] == 4625 and res[i]['Message'].__contains__(usr) and res[i+1]['Message'].__contains__(usr):
                if res[i]['Message'].__contains__(usr):
                        if res[i]['Id'] == "4625":
                            msg = res[i]['Message']
                            msg = msg[msg.index('Account For Which Logon Failed'):msg.index('Failure Information:') - 3]
                            msg = msg.replace('\t', '').replace('\r', '')
                            db.insertReport(res[i], MSG.STATUS_SUSPICIOUS, reportId, (MSG.THRT_WRONG_PASSWD_LOGIN) + '\n' + str(msg), getForensicData(res[i],  "Logon Failure", "4776;4625", "Confidentiality"))
                        else:
                            db.insertReport(res[i], MSG.STATUS_SUSPICIOUS, reportId, (MSG.THRT_WRONG_PASSWD_LOGIN) + '\n' + str(res[i]['Message']), getForensicData(res[i],  "Logon Failure", "4776;4625", "Confidentiality"))


# When someone created a new account in a workstation
def getAddAccountEventStatus(storeName, reportId):
    res = db.getLogDataUsingQuery(storeName, 'Id', ["4793", "4728", "4720", "4722"])
    res = res[::-1]
    for i in range(0, len(res), 4): # (4793, 4728, 4720, 4722)
        if res[i]['Id'] == "4793" and res[i+1]['Id'] == "4728" and res[i+2]['Id'] == "4720" and res[i+3]['Id'] == "4722":
            if res[i]['Message'].__contains__(logonID) and res[i+1]['Message'].__contains__(logonID) and \
                res[i+2]['Message'].__contains__(logonID) and res[i+3]['Message'].__contains__(logonID):
                adminAccMsg = res[i]['Message']
                adminAccName = adminAccMsg[adminAccMsg.index('Account Name:') + len('Account Name:'):adminAccMsg.\
                    index('\n', adminAccMsg.index('Account Name:'))].replace('\t', '').replace('\r', '')
                desktopName = adminAccMsg[adminAccMsg.index('Caller Workstation:') + len('Caller Workstation:'):adminAccMsg.\
                    index('\n', adminAccMsg.index('Caller Workstation:'))].replace('\t', '').replace('\r', '')

                newUserMsg = res[i+2]['Message']
                newUserName = newUserMsg[newUserMsg.index('New Account'):].replace('\t', '').replace('\r', '')
                newUserName = newUserName[newUserName.index('Account Name:'):newUserName.index('Attributes')].strip('\n')

                db.insertReport(res[i], MSG.STATUS_SUSPICIOUS, reportId,
                                (MSG.SUSP_NEW_ACCOUNT_CREATED % (newUserName, adminAccName, desktopName)), getForensicData(res[i],  "Add New Account", "4793;4728;4720;4722", "Confidentiality"))
                db.insertReport(res[i+1], MSG.STATUS_SUSPICIOUS, reportId,
                                (MSG.SUSP_NEW_ACCOUNT_CREATED % (newUserName, adminAccName, desktopName)), getForensicData(res[i+1], "Add New Account", "4793;4728;4720;4722", "Confidentiality"))
                db.insertReport(res[i+2], MSG.STATUS_SUSPICIOUS, reportId,
                                (MSG.SUSP_NEW_ACCOUNT_CREATED % (newUserName, adminAccName, desktopName)), getForensicData(res[i+2], "Add New Account", "4793;4728;4720;4722", "Confidentiality"))
                db.insertReport(res[i+3], MSG.STATUS_SUSPICIOUS, reportId,
                                (MSG.SUSP_NEW_ACCOUNT_CREATED % (newUserName, adminAccName, desktopName)), getForensicData(res[i+3], "Add New Account", "4793;4728;4720;4722", "Confidentiality"))


# When someone deletes a user account in a workstation
def getDelAccountEventStatus(storeName, reportId):
    res = db.getLogDataUsingQuery(storeName, 'Id', ["4733", "4729", "4726"])
    res = res[::-1]
    accntRemoved = {}
    for i in range(0, len(res)):  # (4733, 4729, 4726)
        if res[i]['Id'] == "4726":
            msg = res[i]['Message']
            msg = msg[msg.index('Target Account:') + len('Target Account:'):msg.index('Additional Information')]
            msg = msg.replace('\t', '')
            securityId = msg[msg.index('Security ID:') + len('Security ID:'):msg.index('\n', msg.index('Security ID:'))]
            securityId = securityId.replace('\r', '')
            accName = msg[msg.index('Account Name:') + len('Account Name:'):msg.index('\n', msg.index('Account Name:'))]
            accName = accName.replace('\t', '').replace('\r', '')
            accntRemoved[accName] = securityId

    for acc in accntRemoved.keys():
        for i in range(0, len(res)):
            if res[i]['Message'].__contains__(accntRemoved[acc]) and res[i]['Message'].__contains__(logonID):
                msg = res[i]['Message']
                msg = msg[msg.index('Account Name:'):msg.index('Logon ID')].replace('\t', '').replace('\r', '')
                msg = msg.replace('Account Domain', 'Workstation')
                db.insertReport(res[i], MSG.STATUS_SUSPICIOUS, reportId, (MSG.SUSP_ACCOUNT_DELETED % (acc, msg)), getForensicData(res[i], "Delete User Account", "4733;4729;4726", "Confidentiality"))


# When someone deletes log events
def getEventLogsDeleteEvent(storeName, reportId):
    res = db.getLogDataUsingQuery(storeName, 'Id', ['1102'])
    res = res[::-1]
    accntRemoved = {}
    for i in range(0, len(res)):
        msg = res[i]['Message']
        msg = msg[msg.index('Account Name:'):msg.index('Logon ID:')].replace('\t', '').replace('\r', '').strip('\n')
        # print(MSG.ATTCK_LOG_CLEAR % msg)
        db.insertReport(res[i], MSG.STATUS_ATTACK, reportId, (MSG.ATTCK_LOG_CLEAR % msg), getForensicData(res[i], "Delete User Account", "1102", "Breach of Availability."))


# When someone tries to open/run a file without permission
def getTryRunWithoutAccess(storeName, reportId):
    fileList = []
    res = db.getFailedObjectAccessLogs(storeName)
    for i in range(0, len(res)):
        accName = ''
        lid = ''
        obj = ''
        if res[i]['Id'] == "4656":
            msg = res[i]['Message']

            msg = msg[msg.index('Account Name:') + len('Account Name:'):].strip('\t')
            accName = msg[:msg.index('\n')].replace('\t', '').replace('\r', '')
            msg = msg[msg.index('Logon ID:') + len('Logon ID:'):].strip('\t')
            lid = msg[:msg.index('\n')].replace('\t', '').replace('\r', '')
            msg = msg[msg.index('Object Name:') + len('Object Name:'):].strip('\t')
            obj = msg[:msg.index('\n')].replace('\t', '').replace('\r', '')

            if obj.__contains__(':'):
                if len(fileList) == 0:
                    fileList.append([accName, lid, obj, 1])
                else:
                    there = False
                    for f in fileList:
                        if f[0] == accName and f[1] == lid and f[2] == obj:
                            cnt = f[3]
                            f[3] = cnt + 1
                            there = True
                    if not there:
                        fileList.append([accName, lid, obj, 1])

    for f in fileList:
        if f[3] > 6: # ['Subhamoy', '0xA437DA', 'G:\\task\\xyz_norights.txt', 54]
            for i in range(0, len(res)):
                if res[i]['Message'].__contains__(f[0]) and res[i]['Message'].__contains__(f[1]) and \
                        res[i]['Message'].__contains__(f[2]):
                    db.insertReport(res[i], MSG.STATUS_THREAT, reportId, MSG.THRT_UNWANTED_ACCESS_TRY % (f[0], f[2]), getForensicData(res[i], "Failure Unwanted Access Try Multiple", "4656;4656;4656;4656;4656;4656", "Confidentiality")) # log, status, reportId, reportMsg
        else:
            for i in range(0, len(res)):
                if res[i]['Message'].__contains__(f[0]) and res[i]['Message'].__contains__(f[1]) and \
                        res[i]['Message'].__contains__(f[2]):
                    db.insertReport(res[i], MSG.STATUS_SUSPICIOUS, reportId, MSG.SUSP_UNWANTED_ACCESS_TRY % (f[0], f[2]), getForensicData(res[i], "Unwanted Access Try", "4656", "Confidentiality")) # log, status, reportId, reportMsg


    logs = db.getSuccessObjectAccessLogs(storeName)
    # print(fileList)
    for i in range(0, len(res)):
        msg = res[i]['Message']
        for f in fileList: # ['Subhamoy', '0xA437DA', 'G:\\task\\xyz_norights.txt', 54]
            if f[2].__contains__(':'):
                if msg.__contains__(f[0]) and msg.__contains__(f[1]) and msg.__contains__(f[2]):
                    db.insertReport(res[i], MSG.STATUS_ATTACK, reportId, MSG.ATTCK_UNWANTED_ACCESS % (f[0], f[2]), getForensicData(res[i], "Success Unwanted Access Try Multiple", "4656", "Breach of Confidentiality"))


        # db.insertReport(res[i], MSG.STATUS_ATTACK, reportId, (MSG.ATTCK_LOG_CLEAR % msg))


# When a document is printed
def getPrintDate(storeName, reportId):
    res = db.getPrintLogs(storeName)
    for i in range(0, len(res)):
        db.insertReport(res[i], MSG.STATUS_SUSPICIOUS, reportId, 'Document was printed.', getForensicData(res[i], "Document Printed", "307", "Confidentiality"))


# Fill in the other logs in the log store currently not taken into consideration
def fillInTheUnknowLogs(storeName, reportId):
    logids = db.getKnownLogIds(reportId)
    logs = list(db.getLogDate(storeName)) # 241
    if len(logs) > 100:
        x = 100
    else:
        x = len(logs)
    for i in range(0, x):
        if logs[i]['_id'] in logids:
            continue
        db.insertReport(logs[i], MSG.STATUS_GEN, reportId, 'OK', getForensicData(-1, "", "", ""))


        
def getSessionIDs():
    sesIds = []
    data = db.getAllLogs('wintest')
    for log in data:
        securityId = ''
        loginId = ''
        if log['Message'].__contains__('Security ID'):
            tmpMsgSID = log['Message']
            tmpMsgSID = tmpMsgSID[tmpMsgSID.index('Security ID'):tmpMsgSID.index('\n', tmpMsgSID.index('Security ID'))]
            securityId = tmpMsgSID.replace('\t', '').replace('\n', '').replace('\r', '')
        
        if log['Message'].__contains__('Logon ID'):
            tmpMsgLID = log['Message']
            try:
                tmpMsgLID = tmpMsgLID[tmpMsgLID.index('Logon ID'):tmpMsgLID.index('\n', tmpMsgLID.index('Logon ID'))]
            except:
                tmpMsgLID = tmpMsgLID[tmpMsgLID.index('Logon ID'):]

            loginId = tmpMsgLID.replace('\t', '').replace('\n', '').replace('\r', '')
            if loginId not in sesIds and len(securityId.split('-')) > 6:
                print(str(log['TimeCreated']))
                print(securityId)
                print(loginId)
                sesIds.append(loginId)
                print('************************************')
    
    print(len(sesIds))
        
        
# if __name__ == '__main__':
    # analyzeLogs('wintest') 
#    # analyzeLogs('a2')
#    # fillInTheUnknowLogs('home-log', 'home-log_2019-08-07_16:45:59.625541_0x1E6C1F95')


def getLoginSessions(storeName):
    eventId = ["4648", "4624"]
    res = db.getLogDataUsingQuery(storeName, 'Id', eventId)
    sessionIDs = []
    for i in range(0, len(res)):
        msg = res[i]['Message']
        try:
            msg = msg[msg.index('New Logon:'):msg.index('Logon GUID')]
            msg = msg[msg.index('Logon ID'):msg.index('Network Account Name')]
            msg = re.split('\r', msg)
            logonId = (msg[0]).strip('\n')
            logonId = logonId[logonId.index('0x'):]
            linkedLogonId = (msg[1]).strip('\n')
            linkedLogonId = linkedLogonId[linkedLogonId.index('0x'):]
            sessionIDs.append([logonId, linkedLogonId])
        except:
            continue

    res = db.getLogDataUsingQuery(storeName, 'Id', ["4634"])
    noOfCompleteSessions = 0
    for ses in sessionIDs:
        found = False
        for i in range(0, len(res)):
            msg = res[i]['Message']
            if msg.__contains__(ses[0]) or msg.__contains__(ses[1]):
                noOfCompleteSessions += 1
                found = True
                break
        if found:
            print(ses)


    print(noOfCompleteSessions)

    
    
    
    
    
    
    
    
# def getSessions():
#     db


# def jobGetAccessAttackStatus(storeName):
#     # LoginSuccess, ObjectReadRequest-success/failure, ObjectReadAccess-success, Logoff-Success
#     eventIDs = [4624]
#     res = db.getLogDataUsingQuery(storeName, 'Id', eventIDs)
#     sessionIds = []
#     for r in res:
#         if r['Id'] == 4624:
#             msg = str(r['Message'])
#             msg = msg[msg.index('New Logon'):msg.index('Process Information', msg.index('New Logon'))]
#             msg = msg[msg.index('Logon ID'):msg.index('\n', msg.index('Logon ID'))]
#             logonid = (re.split('\t', msg)[-1]).strip('\r')
#             if logonid not in sessionIds:
#                 sessionIds.append(logonid)
#     threads = []
#     print(sessionIds)
#     try:
#         cnt = 0
#         for ses in sessionIds:
#             if db.checkCompleteSessionStatus(storeName, ses):
#                 cnt += 1
#                 # t = threading.Thread(target=jobGetReadAttackStatus, name='Thread-Ses-' + str(ses), args=(storeName, ses,))
#                 # threads.append(t)
#     except Exception:
#         print('Exception :: jobGetAccessAttackStatus :: Making Thread')
#
#     print(cnt)
#
#     # try:
#     #     for i in range(0, len(threads)):
#     #         threads[i].start()
#     #
#     #     for i in range(0, len(threads)):
#     #         threads[i].join()
#     #
#     # except Exception:
#     #     print('Exception :: jobGetAccessAttackStatus :: Run Thread')
#
#
# def jobGetReadAttackStatus(storeName, ses): # 0 - Regular, 1 - Threat, 2 - Attack
#     eventIDs = [4624, 4656, 4663, 4647]
#     reportId = storeName + '-' + str(datetime.datetime.now()) + '-' + str(ses)
#     log = db.getLogsForAnalyze(storeName, ses, eventIDs)
#     subLogInStatus = False
#     for i in range(1, len(log)-1):
#         if log[i]['Id'] == 4656 and log[i]['Keywords'] in [-9218868437227405312, -9218868437227400000]: # No access threat scenario
#             if log[i+1]['Id'] != 4656: continue
#             countEvt = 0
#             objPrev = log[i]['Message']
#             objPrev = objPrev[objPrev.index('Object Name') + 12:objPrev.index('\n', objPrev.index('Object Name'))].strip('\t')
#             objNext = log[i]['Message']
#             objNext = objNext[objNext.index('Object Name') + 12:objNext.index('\n', objNext.index('Object Name'))].strip('\t')
#
#             if objPrev != objNext: continue
#             sameObjName = 0
#             for j in range(i, i+6):
#                 try:
#                     objName = log[j]['Message']
#                     objName = objName[objName.index('Object Name') + 12:objName.index('\n', objName.index('Object Name'))].strip('\t')
#                     if objPrev == objName: sameObjName += 1
#                     # print(objName)
#                 except:
#                     continue
#             if sameObjName == 6:
#                 for j in range(i, i + 6):
#                     objName = log[j]['Message']
#                     objName = objName[objName.index('Object Name') + 12:objName.index('\n', objName.index('Object Name'))].strip('\t')
#                     userName = log[j]['Message']
#                     userName = userName[userName.index('Account Name')+13:userName.index('\n', userName.index('Account Name'))].strip('\t')
#                     userName = str(userName).strip('\r')
#                     # TODO :: Uncomment Later
#                     db.insertReport(log[j], 1, reportId, 'Threat: User %s tried to access object %s' % (userName, objName))
#             i = i + 6
#         elif log[i]['Id'] == 4656 and log[i]['Keywords'] in [-9214364837600034816, -9214364837600030000]:  # success access threat scenario
#             if log[i+1]['Id'] in [4663, 4656]:
#                 continue
#             else:
#                 if log[i+1]['Id'] == 4624 and log[i+1]['Keywords'] in [-9214364837600034816, -9214364837600030000]: # Success Admin Login
#                     subSessionId = log[i+1]['Message']
#                     subSessionId = subSessionId[subSessionId.index('New Logon:'):subSessionId.index('Linked Logon ID', subSessionId.index('New Logon:'))].strip('\t')
#                     subSessionId = str(subSessionId).strip('\r')
#                     subSessionId = re.split('\n', subSessionId)[::-1][1]
#                     subSessionId = subSessionId.strip('\r').strip('\t')
#                     subSessionId = re.split('\t', subSessionId)[-1]
#                     x = i+2
#                     xCnt = 0
#                     print('Session ID ', subSessionId)
#
#                     while log[x]['Id'] not in [4634, 4647]:
#                         if log[x]['Message'].__contains__('An attempt was made to access an object') and log[x]['Keywords'] in [-9214364837600034816, -9214364837600030000]:
#                             db.insertReport(log[x], 2, reportId, 'Attack')
#                             # print('LOL - ', log[x]['Id'])
#                             # print('LOL - %s' % str(log[x]['Message']))
#                         else:
#                             db.insertReport(log[i], 0, reportId, 'Log Clean')
#
#                         x = x + 1
#
#                     # print('-----------------')
#                     # print(log[i]['Message'])
#                     # print('-----------------')
#                     # print(log[i+1]['Message'])
#                     # print('**********************************************')
#                 elif log[i+1]['Id'] == 4624 and log[i+1]['Keywords'] in [-9218868437227405312, -9218868437227400000]: # Failure Admin Login
#                     db.insertReport(log[i], 1, reportId, 'Log Clean')
#                     # print(log[i+1]['Keywords'])
#         else:
#             # pass
#             # TODO :: Uncomment Later
#             db.insertReport(log[i], 0, reportId, 'Log Clean')
#
#
#
#
# def jobGetAccLoginAttackStatus(storeName):
#     eventIDs = [4648, 4624, 4648]
#     print('checking :: ', eventIDs)
#
# if __name__ == '__main__':
#     # test()
#     jobGetAccessAttackStatus('a2')