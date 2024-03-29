from PyQt4.QtGui import *
from PyQt4.QtCore import *
import DB as db
import datetime
import re


class ViewLogs(QWidget):
        def __init__(self):
            super(ViewLogs, self).__init__()
            layout = QGridLayout()
            layout.setAlignment(Qt.AlignTop)
            self.setLayout(layout)
            select_store = QHBoxLayout()
            store_name = QLabel("<html><h3>Upload ID</h3></html>")
            select_store.addWidget(store_name)
            self.store_value = QComboBox()
            self.store_value.addItems(db.dist_store)
            select_store.addWidget(self.store_value)
            okbtn = QPushButton('OK')
            okbtn.setMinimumSize(10,10)
            select_store.addWidget(okbtn)
            layout.addLayout(select_store,0,0)
            okbtn.clicked.connect(lambda : self.create_table(layout, str(self.store_value.currentText())))

        def create_table(self,layout,text):
            data = db.mycol.find({'Store' : str(text)})
            c = data.count()
            self.show_data = QTableWidget()
            # self.show_data.setColumnCount(27)
            self.show_data.setColumnCount(5)
            self.show_data.setRowCount(c)
            # self.show_data.setHorizontalHeaderLabels(['Id','Message','Version','Qualifiers','Level','Task','Opcode',
            #                                           'Keywords','RecordId','ProviderId','ProviderName','LogName',
            #                                           'ProcessId','ThreadId','MachineName','UserId','TimeCreated'
            #                                              ,'ActivityId','RelatedActivityId','ContainerLog',
            #                                           'MatchedQueryIds','Bookmark','LevelDisplayName',
            #                                           'OpcodeDisplayName','TaskDisplayName',
            #                                           'KeywordsDisplayNames','Properties'])

            self.show_data.setHorizontalHeaderLabels(
                ['Date', 'Time', 'Id', 'Opcode', 'Message'])

            j=0
            for i in data:
                if j==c:
                    break
                else:
                    self.updateTable(j, i)
                    j = j+1
            layout.addWidget(self.show_data)
            count_box = QHBoxLayout()
            countbtn = QPushButton("Count")
            countbtn.setMaximumWidth(80)
            count_box.addWidget(countbtn)
            countbtn.clicked.connect(self.count)
            self.countlnedit = QLineEdit()
            self.countlnedit.setMaximumWidth(100)
            count_box.addWidget(self.countlnedit)
            layout.addLayout(count_box,0,1)

            sort_box = QHBoxLayout()
            sortbtn = QPushButton("Sort Logs")
            sortbtn.setMaximumWidth(80)
            sort_box.addWidget(sortbtn)
            sortbtn.clicked.connect(self.sort)
            self.sort_by = QComboBox()
            self.sort_by.addItems(['Date and Time','User','Machine','Level','Event Id'])
            sort_box.addWidget(self.sort_by)
            layout.addLayout(sort_box, 1, 1)
            query_box = QHBoxLayout()
            query = QPushButton("Query")
            query.setMaximumSize(80,30)
            query_box.addWidget(query)
            # layout.addLayout(query_box,8,0)
            query.clicked.connect(lambda : self.get_q(layout))

        def count(self):
            self.countlnedit.setText(str(self.show_data.rowCount()))

        def sort(self):
            #self.show_data.clear()
            if(str(self.sort_by.currentText())=='Date and Time'):
                sorted = db.mycol.find({'Store' : str(self.store_value.currentText())}).sort('TimeCreated')
                self.show_data.setRowCount(sorted.count())
                j = 0
                for i in sorted:
                    self.updateTable(j, i)
                    j = j+1
            if(str(self.sort_by.currentText())=='Event Id'):
                sorted = db.mycol.find({'Store' : str(self.store_value.currentText())}).sort('Id')
                self.show_data.setRowCount(sorted.count())
                j = 0
                for i in sorted:
                    self.updateTable(j, i)
                    j = j+1
            if(str(self.sort_by.currentText())=='User'):
                sorted = db.mycol.find({'Store' : str(self.store_value.currentText())}).sort('UserId')
                self.show_data.setRowCount(sorted.count())
                j = 0
                for i in sorted:
                    self.updateTable(j, i)
                    j = j+1
            if(str(self.sort_by.currentText())=='Level'):
                sorted = db.mycol.find({'Store' : str(self.store_value.currentText())}).sort('Level')
                self.show_data.setRowCount(sorted.count())
                j = 0
                for i in sorted:
                    self.updateTable(j, i)
                    j = j+1
            if(str(self.sort_by.currentText())=='Machine'):
                sorted = db.mycol.find({'Store' : str(self.store_value.currentText())}).sort('MachineName')
                self.show_data.setRowCount(sorted.count())
                j = 0
                for i in sorted:
                    self.updateTable(j, i)
                    j = j+1

        def get_q(self,layout):
            self.countlnedit.clear()
            queries = QDialog()
            q_lay = QGridLayout()
            queries.setLayout(q_lay)
            queries.setMinimumSize(800,500)
            queries.setStyleSheet('font-size : 18pt;')
            idvbox = QHBoxLayout()
            id_lbl = QLabel("EventId")
            idvbox.addWidget(id_lbl)
            e_id = QLineEdit()
            idvbox.addWidget(e_id)
            q_lay.addLayout(idvbox,0,0)
            msgbox = QHBoxLayout()
            msg_lbl = QLabel("Message")
            msgbox.addWidget(msg_lbl)
            keyword = QLineEdit()
            msgbox.addWidget(keyword)
            q_lay.addLayout(msgbox,1,0)
            lvlvbox = QHBoxLayout()
            lvl_lbl = QLabel("Level")
            lvlvbox.addWidget(lvl_lbl)
            level = QLineEdit()
            lvlvbox.addWidget(level)
            q_lay.addLayout(lvlvbox,0,1)
            q_ok = QPushButton("OK")
            q_ok.setMaximumSize(60,35)
            q_lay.addWidget(q_ok,2,2)
            q_ok.clicked.connect(lambda : self.q_fetch(layout,e_id.text(),level.text(),keyword.text()))
            queries.exec_()

        def q_fetch(self,layout,id,level,msg):
            level = int(str(level))
            msg = str(msg)
            id = int(str(id))
            filter = db.mycol.find({"Id" : id , "Level" : level, 'Store' : str(self.store_value.currentText()), 'Message': {'$regex': msg}})
            self.show_data.clear()
            self.show_data.setRowCount(filter.count())
            j = 0
            for i in filter:
                self.updateTable(j, i)
                j = j+1

        def updateTable(self, j, i): # 'Date', 'Time', 'Id', 'Opcode', 'Message'

            dt = str(datetime.datetime.fromtimestamp(1347517370).strftime('%d-%m-%Y %H:%M:%S'))
            dt = re.split(' ', dt)
            self.show_data.setItem(j, 0, QTableWidgetItem(str(dt[0])))
            self.show_data.setItem(j, 1, QTableWidgetItem(str(dt[1])))
            self.show_data.setItem(j, 2, QTableWidgetItem(str(i["Id"])))
            self.show_data.setItem(j, 3, QTableWidgetItem(str(i["Keywords"])))
            # self.show_data.setItem(j, 6, QTableWidgetItem(str(i["Opcode"])))
            self.show_data.setItem(j, 4, QTableWidgetItem(str(i["Message"])))
'''
            self.show_data.setItem(j, 0, QTableWidgetItem(str(i["Id"])))
            self.show_data.setItem(j, 1, QTableWidgetItem(str(i["Message"])))
            self.show_data.setItem(j, 2, QTableWidgetItem(str(i["Version"])))
            self.show_data.setItem(j, 3, QTableWidgetItem(str(i["Qualifiers"])))
            self.show_data.setItem(j, 4, QTableWidgetItem(str(i["Level"])))
            self.show_data.setItem(j, 5, QTableWidgetItem(str(i["Task"])))
            self.show_data.setItem(j, 6, QTableWidgetItem(str(i["Opcode"])))
            self.show_data.setItem(j, 7, QTableWidgetItem(str(i["Keywords"])))
            self.show_data.setItem(j, 8, QTableWidgetItem(str(i["RecordId"])))
            self.show_data.setItem(j, 9, QTableWidgetItem(str(i["ProviderId"])))
            self.show_data.setItem(j, 10, QTableWidgetItem(str(i["ProviderName"])))
            self.show_data.setItem(j, 11, QTableWidgetItem(str(i["LogName"])))
            self.show_data.setItem(j, 12, QTableWidgetItem(str(i["ProcessId"])))
            self.show_data.setItem(j, 13, QTableWidgetItem(str(i["ThreadId"])))
            self.show_data.setItem(j, 14, QTableWidgetItem(str(i["MachineName"])))
            self.show_data.setItem(j, 15, QTableWidgetItem(str(i["UserId"])))
            self.show_data.setItem(j, 16, QTableWidgetItem(str(i["TimeCreated"])))
            self.show_data.setItem(j, 17, QTableWidgetItem(str(i["ActivityId"])))
            self.show_data.setItem(j, 18, QTableWidgetItem(str(i["RelatedActivityId"])))
            self.show_data.setItem(j, 19, QTableWidgetItem(str(i["ContainerLog"])))
            self.show_data.setItem(j, 20, QTableWidgetItem(str(i["MatchedQueryIds"])))
            self.show_data.setItem(j, 21, QTableWidgetItem(str(i["Bookmark"])))
            self.show_data.setItem(j, 22, QTableWidgetItem(str(i["LevelDisplayName"])))
            self.show_data.setItem(j, 23, QTableWidgetItem(str(i["OpcodeDisplayName"])))
            self.show_data.setItem(j, 24, QTableWidgetItem(str(i["TaskDisplayName"])))
            self.show_data.setItem(j, 25, QTableWidgetItem(str(i["KeywordsDisplayNames"])))
            self.show_data.setItem(j, 26, QTableWidgetItem(str(i["Properties"])))
'''
