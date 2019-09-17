import datetime
from PyQt4.QtGui import *
from PyQt4.QtCore import *
import AnalyseLogs as analyse
import sys, random
import Configuration as cfg
import re
import VisualizeLogsDBOps as db
import LogAnalyzeLogs as analyze
import LogAnalyzeDBOps as dban

class VisualizationLogs(QWidget):
    def __init__(self):
        super(VisualizationLogs, self).__init__()

        mainLayout = QGridLayout()

        self.lblReportNames = QLabel('Report IDs')
        self.comboReportNames = QComboBox()
        
        self.comboStoreName = QComboBox()
        self.btnAnalyze = QPushButton('Analyze')

        self.filter = QComboBox()

        self.table = QTableWidget()
        self.table.insertColumn(0)
        self.table.insertColumn(1)
        self.table.insertColumn(2)
        self.table.insertColumn(3)
        self.table.insertColumn(4)
        self.table.setHorizontalHeaderLabels(
            ['Date', 'Time', 'Status', 'Report', 'Log-Message'])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)

        # self.table.setColumnWidth(2, 150)
        # self.table.setColumnWidth(3, 180)

        self.txtFullValue = QTextEdit()
        self.txtFullValue.setMinimumHeight(150)

        reportNames = db.getUniqueReportNames()

        self.comboReportNames.addItems(reportNames)
        self.filter.addItems(['', 'All', 'General', 'Suspicious', 'Threat', 'Attack'])

        self.comboReportNames.currentIndexChanged.connect(self.loadReport)
        self.filter.currentIndexChanged.connect(self.loadFilteredReport)
        self.table.cellClicked.connect(self.showFullValue)
        self.comboStoreName.currentIndexChanged.connect(self.selectedStoreName)
        self.btnAnalyze.clicked.connect(self.analyzeLogs)

        mainLayout.addWidget(QLabel('Upload ID'), 0, 0)
        mainLayout.addWidget(self.comboStoreName, 0, 1)
        mainLayout.addWidget(self.btnAnalyze, 0, 2)
        mainLayout.addWidget(self.lblReportNames, 1, 0)
        mainLayout.addWidget(self.comboReportNames, 1, 1)
        mainLayout.addWidget(self.filter, 1, 2)
        mainLayout.addWidget(self.txtFullValue, 2, 0, 1, 3)
        mainLayout.addWidget(self.table, 3, 0, 1, 3)

        self.comboStoreName.clear()

        # Add Contents
        self.comboStoreName.addItems(dban.getUniqueStoreName())

        self.setLayout(mainLayout)

    def loadReport(self):
        if self.comboReportNames.currentText() != '':
            # print(str(self.comboReportNames.currentText()))
            self.filter.setCurrentIndex(1)
            self.table.clear()
            self.table.setHorizontalHeaderLabels(
                ['Date', 'Time', 'Status', 'Report', 'Log-Message'])
            # self.table.horizontalHeader().setStretchLastSection(True)
            self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
            reports = db.getFullReport(str(self.comboReportNames.currentText()))
            self.table.setRowCount(len(reports))
            for i in range(0, len(reports)):
                date_time = ''
                try:
                    date_time = str(datetime.datetime.fromtimestamp(float(reports[i]['TimeCreated'])).strftime('%Y-%m-%d %H:%M:%S'))
                    date_time = re.split(' ', date_time)
                except:
                    date_time = re.split(' ', date_time)

                if date_time[0] == '': # ISODate("2019-08-08T21:18:54Z")
                    dt = str(reports[i]['TimeCreated'])
                    date_time = re.split(' ', dt)

                self.table.setItem(i, 0, QTableWidgetItem(date_time[0]))
                self.table.setItem(i, 1, QTableWidgetItem(date_time[1]))
                # if reports[i]['attack_status'] == 0:
                #     self.table.setItem(i, 2, QTableWidgetItem('General'))
                # elif reports[i]['attack_status'] == 1:
                #     self.table.setItem(i, 2, QTableWidgetItem('Suspicious'))
                # elif reports[i]['attack_status'] == 2:
                #     self.table.setItem(i, 2, QTableWidgetItem('Threat'))
                # elif reports[i]['attack_status'] == 3:
                #     self.table.setItem(i, 2, QTableWidgetItem('Attack'))

                self.table.setItem(i, 2, QTableWidgetItem(str(reports[i]['attack_status'])))
                self.table.setItem(i, 3, QTableWidgetItem(reports[i]['report_msg']))
                self.table.setItem(i, 4, QTableWidgetItem(reports[i]['Message']))

                colorObj = Qt.white
                if reports[i]['attack_status'] == 1: # Suspicious
                    colorObj = Qt.cyan
                elif reports[i]['attack_status'] == 2: # Threat
                    colorObj = Qt.yellow
                elif reports[i]['attack_status'] == 3: # Attack
                    colorObj = Qt.red

                self.table.item(i, 0).setBackground(colorObj)
                self.table.item(i, 1).setBackground(colorObj)
                self.table.item(i, 2).setBackground(colorObj)
                self.table.item(i, 3).setBackground(colorObj)
                self.table.item(i, 4).setBackground(colorObj)

        else:
            self.table.clear()
            self.table.setRowCount(0)

    def loadFilteredReport(self):
        filterLvl = 0
        refreshStatus = False
        if self.comboReportNames.currentText() != '':
            if self.filter.currentText() in ['', 'All']:
                self.loadReport()
            elif self.filter.currentText() == 'General':
                filterLvl = 0
                refreshStatus = True
            elif self.filter.currentText() == 'Suspicious':
                filterLvl = 1
                refreshStatus = True
            elif self.filter.currentText() == 'Threat':
                filterLvl = 2
                refreshStatus = True
            elif self.filter.currentText() == 'Attack':
                filterLvl = 3
                refreshStatus = True
        else:
            self.loadReport()

        if refreshStatus:
            self.table.clear()
            self.table.setHorizontalHeaderLabels(
                ['Date', 'Time', 'Status', 'Report', 'Log-Message'])
            # self.table.horizontalHeader().setStretchLastSection(True)
            self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
            reports = db.getFullReport(str(self.comboReportNames.currentText()))
            self.table.setRowCount(len(reports))
            cnt = 0
            for i in range(0, len(reports)):
                if str(reports[i]['attack_status']) == str(filterLvl):
                    # print(reports[i]['TimeCreated'])
                    try:
                        date_time = str(datetime.datetime.fromtimestamp(float(reports[i]['TimeCreated'])).strftime('%Y-%m-%d %H:%M:%S'))
                    except:
                        date_time = str(reports[i]['TimeCreated'])
                    date_time = re.split(' ', date_time)
                    self.table.setItem(cnt, 0, QTableWidgetItem(date_time[0]))
                    self.table.setItem(cnt, 1, QTableWidgetItem(date_time[1]))
                    self.table.setItem(cnt, 2, QTableWidgetItem(str(reports[i]['attack_status'])))
                    self.table.setItem(cnt, 3, QTableWidgetItem(reports[i]['report_msg']))
                    self.table.setItem(cnt, 4, QTableWidgetItem(reports[i]['Message']))

                    colorObj = Qt.white
                    if reports[i]['attack_status'] == 1: # Suspicious
                        colorObj = Qt.cyan
                    elif reports[i]['attack_status'] == 2: # Threat
                        colorObj = Qt.yellow
                    elif reports[i]['attack_status'] == 3: # Attack
                        colorObj = Qt.red

                    self.table.item(cnt, 0).setBackground(colorObj)
                    self.table.item(cnt, 1).setBackground(colorObj)
                    self.table.item(cnt, 2).setBackground(colorObj)
                    self.table.item(cnt, 3).setBackground(colorObj)
                    self.table.item(cnt, 4).setBackground(colorObj)

                    cnt += 1


    def showFullValue(self):
        row = self.table.currentRow()
        col = self.table.currentColumn()
        textV = self.table.item(row, col).text()
        self.txtFullValue.setText(textV)


    def selectedStoreName(self):
        if self.comboStoreName.currentText() != '':
            self.btnAnalyze.setEnabled(True)
        else:
            self.btnAnalyze.setEnabled(False)

    def analyzeLogs(self):
        analyze.analyzeLogs(str(self.comboStoreName.currentText()))
        self.comboReportNames.clear()
        reportNames = db.getUniqueReportNames()
        self.comboReportNames.addItems(reportNames)
