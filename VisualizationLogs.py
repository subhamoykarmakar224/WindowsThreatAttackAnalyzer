import datetime
from PyQt4.QtGui import *
from PyQt4.QtCore import *
import AnalyseLogs as analyse
import sys, random
import Configuration as cfg
import re
import VisualizeLogsDBOps as db

class VisualizationLogs(QWidget):
    def __init__(self):
        super(VisualizationLogs, self).__init__()

        mainLayout = QGridLayout()

        self.lblReportNames = QLabel('Report IDs')
        self.comboReportNames = QComboBox()
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

        mainLayout.addWidget(self.lblReportNames, 0, 0)
        mainLayout.addWidget(self.comboReportNames, 0, 1)
        mainLayout.addWidget(self.filter, 0, 2)
        mainLayout.addWidget(self.txtFullValue, 1, 0, 1, 3)
        mainLayout.addWidget(self.table, 2, 0, 1, 3)

        self.setLayout(mainLayout)

    def loadReport(self):
        if self.comboReportNames.currentText() != '':
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
                self.table.setItem(i, 0, QTableWidgetItem(date_time[0]))
                self.table.setItem(i, 1, QTableWidgetItem(date_time[1]))
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
            for i in range(0, len(reports)):
                if str(reports[i]['attack_status']) == str(filterLvl):
                    date_time = str(datetime.datetime.fromtimestamp(float(reports[i]['TimeCreated'])).strftime('%Y-%m-%d %H:%M:%S'))
                    date_time = re.split(' ', date_time)
                    self.table.setItem(i, 0, QTableWidgetItem(date_time[0]))
                    self.table.setItem(i, 1, QTableWidgetItem(date_time[1]))
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


    def showFullValue(self):
        row = self.table.currentRow()
        col = self.table.currentColumn()
        textV = self.table.item(row, col).text()
        self.txtFullValue.setText(textV)



    #     layout = QGridLayout()
    #     store = QHBoxLayout()
    #     store_name = QLabel("<html><h3>Upload ID</h3></html>")
    #     store.addWidget(store_name)
    #     store_value = QComboBox()
    #     store_value.addItems(db.dist_store)
    #     store.addWidget(store_value)
    #     okbtn = QPushButton("OK")
    #     okbtn.clicked.connect(lambda: self.show_charts(layout,str(store_value.currentText())))
    #     store.addWidget(okbtn)
    #
    #     layout.addLayout(store,0,0)
    #
    #     self.figure = plt.figure()
    #     self.drawing = self.figure.add_subplot(111)
    #     self.canvas = matplotlib.backends.backend_qt4agg.FigureCanvasQTAgg(self.figure)
    #
    #
    #
    #     self.setLayout(layout)
    #
    # def show_charts(self,layout,t):
    #     d = db.mycol.find({'Store' : str(t)})
    #     #print(d.count())
    #     data = list(d)
    #     row = 0
    #     count = 0
    #     attack = 0
    #     threat = 0
    #     regular = 0
    #     for i in data:
    #         if i['Id'] == 1102:
    #             threat = threat + 1
    #         elif i['Id'] == 4663:
    #             if (re.search('Accesses:\\t\\tDELETE', i['Message']) != None):
    #                 threat = threat + 1
    #                 for c in range(count-1,-1,-1):
    #                     if (data[c]['Id'] == 4660):
    #                         attack = attack + 1
    #                         break
    #                     # else:
    #                     	# print('NOT 4660')
    #             elif (re.search('Accesses:\\t\\tReadData', i['Message']) != None):
    #                 threat = threat + 1
    #             elif (re.search('Accesses:\\t\\tWriteData', i['Message']) != None):
    #                 attack = attack + 1
    #             else:
    #             	regular = regular + 1
    #         elif i['Id'] != 4660:
    #             regular = regular + 1
    #         count = count + 1
    #     #print(threat, attack, regular)
    #     # plt.show()
    #
    #     axis = plt.subplot2grid((6,6),(0,0),rowspan = 6,colspan = 6)
    #     axis.pie([attack,threat,regular],colors = ['r', 'y', 'g'], startangle = 90, shadow = False, explode=[0.2, 0, 0])
    #     axis.set_title('Regular Vs Threat Vs Attack')
    #     axis.legend(['%s Attacks' % str(attack),'%s Threats' % str(threat),'%s Regular' % str(regular)])
    #     layout.addWidget(self.canvas, 1, 0)
    #
    #
    #
    #     # scene = QGraphicsScene()
    #     # threat = analyse.AnalyseLogs.show_alert.threat
    #     # vbox = QVBoxLayout()
    #     # self.setLayout(vbox)
    #     # lbl = QLabel(threat)
    #     # vbox.addWidget(lbl)
    #     # scene = QGraphicsScene()
    #     # families = [1,2,3,4,5,6,7]
    #     # total = 0
    #     # colours = []
    #     # set_angle = 0
    #     # count1 = 0
    #     # total = sum(families)
    #     # for count in range(len(families)):
    #     #     number = []
    #     #     for count in range(3):
    #     #         number.append(random.randrange(0, 255))
    #     #     colours.append(QColor(number[0],number[1],number[2]))
    #     # for family in families:
    #     #     angle = round(family/total*16*360)
    #     #     ellipse = QGraphicsEllipseItem(0,0,400,400)
    #     #     ellipse.setPos(0,0)
    #     #     ellipse.setStartAngle(set_angle)
    #     #     ellipse.setSpanAngle(angle)
    #     #     ellipse.setBrush(colours[count1])
    #     #     set_angle += angle
    #     #     count1 +=1
    #     #     scene.addItem(ellipse)
    #     # view = QGraphicsView(scene)
    #     # view.show()
    #
    #
