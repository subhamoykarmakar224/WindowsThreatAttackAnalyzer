# GENERAL
STATUS_GEN = 0

# SUSPICIOUS
STATUS_SUSPICIOUS = 1
SUSP_POLICY_CHANGE = 'A Audit Policy was changed by %s.'
SUSP_WRONG_PASSWD_LOGIN = 'Attempt was made to login to an account.'
SUSP_NEW_ACCOUNT_CREATED = 'A new account was created.\nNew %s, \nCreated by %s \nWorkstation: %s'
SUSP_ACCOUNT_DELETED = 'Account %s was removed by,\n%s'
SUSP_UNWANTED_ACCESS_TRY = 'The User %s tried to access a file.\nLocation: %s'

# THREAT
STATUS_THREAT = 2
THRT_WRONG_PASSWD_LOGIN = 'Attempt was made to login to an account.'
THRT_UNWANTED_ACCESS_TRY = 'The User %s tried to access a file multiple times.\nLocation: %s'

# ATTACK
STATUS_ATTACK = 3
ATTCK_LOG_CLEAR = 'Logs were cleared by,\n%s'
ATTCK_UNWANTED_ACCESS = 'The User %s accessed a file which was unauthorized.\nLocation: %s'
