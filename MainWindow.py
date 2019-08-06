from PyQt4.QtGui import *
import Configuration as cfg

import UploadLogs as upload
import ViewLogs as view
import AnalyseLogs as analyse
import VisualizationLogs as visualize
import ReportLogs as report


class MainWindowApplication(QMainWindow):
    def __init__(self):
        super(MainWindowApplication, self).__init__()
        self.initUi()

    def initUi(self):
        self.setWindowTitle(cfg.APPLICATION_TITLE)
        self.setMinimumSize(850, 850)

        vLayout = QVBoxLayout()

        self.tabsTitle = []
        for tab in cfg.TABS:
            self.tabsTitle.append(tab[1])

        tabGroup = QTabWidget()
        vLayout.addWidget(tabGroup)

        tabGroup.addTab(upload.UploadLogs(), self.tabsTitle[0])
        tabGroup.addTab(view.ViewLogs(), self.tabsTitle[1])
        tabGroup.addTab(analyse.AnalyseLogs(), self.tabsTitle[2])
        tabGroup.addTab(visualize.VisualizationLogs(), self.tabsTitle[3])
        tabGroup.addTab(report.ReportLogs(), self.tabsTitle[4])

        # Listener
        tabGroup.currentChanged.connect(self.refreshTab)

        # setting central widget
        mainVLayoutWidget = QWidget()
        mainVLayoutWidget.setLayout(vLayout)
        self.setCentralWidget(mainVLayoutWidget)
        
        # self.setStyleSheet('font-size : 18pt;')

        # self.showMaximized()
        self.show()

    def refreshTab(self, tabIndex):
        pass
