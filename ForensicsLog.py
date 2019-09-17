from PyQt4.QtGui import *
from PyQt4.QtCore import *
import ForensicsLogDBOps as db

class ForensicsLog(QWidget):
    def __init__(self):
        super(ForensicsLog, self).__init__()
        # Main Layout
        self.mainGridLayout = QGridLayout()

        # Sub Layout

        # Sub Layout Properties
        self.mainGridLayout.setAlignment(Qt.AlignTop)

        # Widget
        self.lblReport = QLabel('Report')
        self.comboReport = QComboBox()
        self.btnShowReport = QPushButton('Show')
        self.btnRefreshReportList = QPushButton('Refresh')
        self.table = QTableWidget()

        # Widget Properties
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(['Date&Time', 'Type', 'Data'])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        
        # Listeners
        self.btnShowReport.clicked.connect(self.loadReportVal)

        # Add to Sub Layout

        # Add to main layout
        self.mainGridLayout.addWidget(self.lblReport, 0, 0)
        self.mainGridLayout.addWidget(self.comboReport, 0, 1)
        self.mainGridLayout.addWidget(self.btnShowReport, 0, 2)
        self.mainGridLayout.addWidget(self.btnRefreshReportList, 0, 3)
        self.mainGridLayout.addWidget(self.table, 1, 0, 1, 4)

        # Set the main layout
        self.setLayout(self.mainGridLayout)

        self.loadReports()
    
    def loadReports(self):
        self.comboReport.clear()
        self.comboReport.addItems(db.getUniqueReports())

    def loadReportVal(self):
        self.table.clearContents()
        if self.comboReport.currentText == '':
            return
        logs = db.getReports(str(self.comboReport.currentText()))
        multiplyVal = 7
        self.table.setRowCount(multiplyVal * len(logs))
        colCnt = 0
        logCnt = 0
        for i in range(0, multiplyVal * len(logs), multiplyVal):
            self.table.setItem(i, 0, QTableWidgetItem(str(logs[logCnt]['TimeCreated'])))
            self.table.setItem(i, 1, QTableWidgetItem('Message'))
            self.table.setItem(i, 2, QTableWidgetItem(str(logs[logCnt]['Message'])))
            self.table.item(i, 0).setBackground(Qt.gray)
            self.table.item(i, 1).setBackground(Qt.gray)
            self.table.item(i, 2).setBackground(Qt.gray)
            self.table.setItem(i+1, 1, QTableWidgetItem('Who?'))
            self.table.setItem(i+1, 2, QTableWidgetItem(str(logs[logCnt]['who'])))
            self.table.setItem(i+2, 1, QTableWidgetItem('From-Where?'))
            self.table.setItem(i+2, 2, QTableWidgetItem(str(logs[logCnt]['fromwhere'])))
            self.table.setItem(i+3, 1, QTableWidgetItem('When?'))
            self.table.setItem(i+3, 2, QTableWidgetItem(str(logs[logCnt]['when'])))
            self.table.setItem(i+4, 1, QTableWidgetItem('What?'))
            self.table.setItem(i+4, 2, QTableWidgetItem(str(logs[logCnt]['what'])))
            self.table.setItem(i+5, 1, QTableWidgetItem('How?'))
            self.table.setItem(i+5, 2, QTableWidgetItem(str(logs[logCnt]['how'])))
            self.table.setItem(i+6, 1, QTableWidgetItem('Why?'))
            self.table.setItem(i+6, 2, QTableWidgetItem(str(logs[logCnt]['why'])))
            logCnt += 1

        # self.show_data.setItem(j, 0, QTableWidgetItem(str(dt[0])))
        # self.show_data.setItem(j, 1, QTableWidgetItem(str(dt[1])))
        # self.show_data.setItem(j, 2, QTableWidgetItem(str(i["Id"])))

        # 'Message': log['Message'],
        # 'who': forensic['who'],
        # 'fromwhere': forensic['fromwhere'],
        # 'when': forensic['when'],
        # 'what': forensic['what'],
        # 'how': forensic['how'],
        # 'why': forensic['why']