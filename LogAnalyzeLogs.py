import threading
import re
import datetime
import LogAnalyzeDBOps as db
import Messages as MSG

logonID = '0x1E6C1F95' # Admin actions
linkedLogonID = '0x1E6C1FFB' # Other actions


def analyzeLogs(storeName):
    reportId = storeName + '_' + str(datetime.datetime.now()).replace(' ', '_') + '_' + str(logonID)
    # reportId = 'r1'
    getPolicyChangeEventStatus(storeName, reportId)



def getPolicyChangeEventStatus(storeName, reportId):
    cnt = 0
    res = db.getLogDataUsingQuery(storeName, 'Id', [4719])
    for i in range(0, len(res)):
        msg = res[i]['Message']
        if msg.__contains__(logonID) or msg.__contains__(linkedLogonID): # insertReport(log, status, reportId, reportMsg)
            accMsg = msg
            accMsg = accMsg[accMsg.index('Account Name') + len('Account Name:'):accMsg.index('Account Domain')].replace('\t', '')
            accMsg = accMsg[:len(accMsg)-2]
            msg = msg[msg.index('Category'):].replace('\t', '')
            db.insertReport(res[i], MSG.STATUS_SUSPICIOUS, reportId, (MSG.SUSP_POLICY_CHANGE % accMsg) + '\n' + str(msg))
    print(cnt)





if __name__ == '__main__':
    analyzeLogs('home-log')



def getLoginSessions(storeName):
    eventId = [4648, 4624]
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

    res = db.getLogDataUsingQuery(storeName, 'Id', [4634])
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