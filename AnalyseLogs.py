from PyQt4.QtGui import *
from PyQt4.QtCore import *
import LogAnalyzeDBOps as db
import LogAnalyzeLogs as analyze
import pymongo
import sys
import re
import datetime as dt

class AnalyseLogs(QWidget):
    def __init__(self):
        super(AnalyseLogs, self).__init__()

        # Main Layout
        self.mainVBoxLayout = QVBoxLayout()

        # Sub Layout
        self.optHBoxLayout = QHBoxLayout()

        # Sub Layout Properties

        # Widget
        self.lblStoreName = QLabel('Store Name')
        self.comboStoreName = QComboBox()
        self.btnAnalyze = QPushButton('Analyze')
        self.lblFilter = QLabel('Filter')
        self.comboFilters = QComboBox()
        self.tableAnalyzeResults = QTableWidget()

        # Widget Properties
        self.lblFilter.setAlignment(Qt.AlignRight)
        self.tableAnalyzeResults.insertColumn(0)
        self.tableAnalyzeResults.insertColumn(1)
        self.tableAnalyzeResults.insertColumn(2)
        self.tableAnalyzeResults.setHorizontalHeaderLabels(['Date&Time', 'EventID', 'Message'])
        self.tableAnalyzeResults.horizontalHeader().setStretchLastSection(True)
        self.tableAnalyzeResults.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.tableAnalyzeResults.setColumnWidth(0, 200)

        # Listeners
        self.comboStoreName.currentIndexChanged.connect(self.selectedStoreName)
        self.btnAnalyze.clicked.connect(self.analyzeLogs)

        # Add to Sub Layout
        self.optHBoxLayout.addWidget(self.lblStoreName)
        self.optHBoxLayout.addWidget(self.comboStoreName)
        self.optHBoxLayout.addWidget(self.btnAnalyze)
        self.optHBoxLayout.addWidget(self.lblFilter)
        self.optHBoxLayout.addWidget(self.comboFilters)

        # Add to main layout
        self.mainVBoxLayout.addLayout(self.optHBoxLayout)
        self.mainVBoxLayout.addWidget(self.tableAnalyzeResults)

        # Set the main layout
        self.setLayout(self.mainVBoxLayout)

        # Refresh Content
        self.refreshContent()

    def refreshContent(self):
        # Clear items
        self.comboStoreName.clear()
        self.comboFilters.clear()

        # Add Contents
        self.comboStoreName.addItems(db.getUniqueStoreName())
        self.comboFilters.addItems(['All', 'General', 'Thread', 'Attack'])
        self.comboFilters.setEnabled(False)

    def selectedStoreName(self):
        if self.comboStoreName.currentText() != '':
            self.btnAnalyze.setEnabled(True)
        else:
            self.btnAnalyze.setEnabled(False)

    def analyzeLogs(self):
        analyze.analyzeLogs(str(self.comboStoreName.currentText()))


