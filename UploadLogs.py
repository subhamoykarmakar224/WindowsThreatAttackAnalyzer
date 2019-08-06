from PyQt4.QtGui import *
from PyQt4.QtCore import *
import parse as win_parse
import os


class UploadLogs(QWidget):
    def __init__(self):
        super(UploadLogs, self).__init__()
        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignTop)
        sublay = QHBoxLayout()
        pltlayout = QHBoxLayout()
        platform = QLabel('<html><h2>Platform</h2></html>')
        platform.setMinimumWidth(100)
        platform.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        pltlayout.addWidget(platform)
        self.pltmenu = QComboBox()
        self.pltmenu.addItems(['windows', 'linux'])
        self.pltmenu.activated[str].connect(self.plat)
        pltlayout.addWidget(self.pltmenu)
        sublay.addLayout(pltlayout)


        ctglayout = QHBoxLayout()
        category = QLabel('<html><h2>Category</h2></html>')
        category.setMinimumWidth(100)
        category.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        ctglayout.addWidget(category)
        self.ctgmenu = QComboBox()
        ctglayout.addWidget(self.ctgmenu)
        sublay.addLayout(ctglayout)
        layout.addLayout(sublay)

        storeLayout = QHBoxLayout()
        lblStoreName = QLabel('<html><h2>Upload ID</h2></html>')
        storeLayout.addWidget(lblStoreName)
        self.lnEdtStoreName = QLineEdit()
        storeLayout.addWidget(self.lnEdtStoreName)
        layout.addLayout(storeLayout)

        filelayout = QHBoxLayout()
        self.file = QLineEdit()
        filelayout.addWidget(self.file)
        browse = QPushButton('Browse')
        filelayout.addWidget(browse)
        btnok = QPushButton('OK')
        filelayout.addWidget(btnok)
        layout.addLayout(filelayout)
        btnok.clicked.connect(self.ok_store)
        browse.clicked.connect(self.browse_file)
        self.setLayout(layout)
        

    def plat(self):
        if str(self.pltmenu.currentText())=='windows':
            self.ctgmenu.clear()
            self.ctgmenu.addItems(['Application','Security','System','Management'])
        else:
            self.ctgmenu.clear()
            self.ctgmenu.addItems(['Application','Event','System','Service'])

    def ok_store(self):
        win_parse.windowsLogParse(str(self.file.text()),self.lnEdtStoreName.text())

    def browse_file(self):
        filePath = QFileDialog.getOpenFileName(self, 'Open File', "", '*.csv')
        self.file.setText(filePath)
