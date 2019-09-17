from PyQt4.QtGui import *
from PyQt4.QtCore import *
import matplotlib.pyplot as plt
import matplotlib.backends.backend_qt4agg
import ReportDBOps as db

class ReportLogs(QWidget):
    def __init__(self):
        super(ReportLogs, self).__init__()
        # Main Layout
        self.mainGridLayout = QGridLayout()

        # Sub Layout

        # Sub Layout Properties
        # self.mainGridLayout.setAlignment(Qt.AlignTop)

        # Widget
        self.lblReport = QLabel('Report')
        self.comboReport = QComboBox()
        self.btnShowReport = QPushButton('Show')
        self.btnRefreshReportList = QPushButton('Refresh')

        # Widget Properties

        # Listeners
        self.btnRefreshReportList.clicked.connect(self.loadReportList)
        self.btnShowReport.clicked.connect(self.loadReport)

        # Add to Sub Layout

        # Add to main layout
        self.mainGridLayout.addWidget(self.lblReport, 0, 0)
        self.mainGridLayout.addWidget(self.comboReport, 0, 1)
        self.mainGridLayout.addWidget(self.btnShowReport, 0, 2)
        self.mainGridLayout.addWidget(self.btnRefreshReportList, 0, 3)

        # Set the main layout
        self.setLayout(self.mainGridLayout)

        self.loadReportList()

    def loadReportList(self):
        self.comboReport.clear()
        self.comboReport.addItems(db.getUniqueReports())

    def loadReport(self):
        if self.comboReport.currentText() != '':
            try:
                self.mainGridLayout.itemAt(4).widget().deleteLater()
            except:
                print('L')
            self.drawPlot()
            counts = db.getReportCounts(str(self.comboReport.currentText())) # [genCount, suspCount, threatCount, attackCount]
            
            axis = plt.subplot2grid((6, 6), (0, 0), rowspan=6, colspan=6)
            axis.pie([counts[3], counts[2], counts[1], counts[0]], colors=['r', 'y', 'c', 'g'], startangle=90, shadow=False, explode=[0.2, 0, 0, 0])
            axis.set_title('Regular Vs Suspicious Vs Insider-Threat Vs Insider-Attack')
            axis.legend(['%s Insider Attack' % str(counts[3]), '%s Insider Threat' % str(counts[2]), '%s Suspicious' % str(counts[1]), '%s Regular' % str(counts[0])])
            self.mainGridLayout.addWidget(self.canvas, 1, 0, 1, 4)

    def drawPlot(self):
        self.figure = plt.figure()
        self.drawing = self.figure.add_subplot(121)
        self.canvas = matplotlib.backends.backend_qt4agg.FigureCanvasQTAgg(self.figure)
