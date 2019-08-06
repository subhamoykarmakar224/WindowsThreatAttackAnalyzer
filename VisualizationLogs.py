from PyQt4.QtGui import *
import AnalyseLogs as analyse
import sys, random
import Configuration as cfg
import DB as db
import re
import matplotlib.pyplot as plt
import matplotlib.backends.backend_qt4agg


class VisualizationLogs(QWidget):
    def __init__(self):
        super(VisualizationLogs, self).__init__()
        layout = QGridLayout()
        store = QHBoxLayout()
        store_name = QLabel("<html><h3>Upload ID</h3></html>")
        store.addWidget(store_name)
        store_value = QComboBox()
        store_value.addItems(db.dist_store)
        store.addWidget(store_value)
        okbtn = QPushButton("OK")
        okbtn.clicked.connect(lambda: self.show_charts(layout,str(store_value.currentText())))
        store.addWidget(okbtn)

        layout.addLayout(store,0,0)

        self.figure = plt.figure()
        self.drawing = self.figure.add_subplot(111)
        self.canvas = matplotlib.backends.backend_qt4agg.FigureCanvasQTAgg(self.figure)

        

        self.setLayout(layout)

    def show_charts(self,layout,t):
        d = db.mycol.find({'Store' : str(t)})
        #print(d.count())
        data = list(d)
        row = 0
        count = 0
        attack = 0
        threat = 0
        regular = 0
        for i in data:
            if i['Id'] == 1102:
                threat = threat + 1
            elif i['Id'] == 4663:
                if (re.search('Accesses:\\t\\tDELETE', i['Message']) != None):
                    threat = threat + 1
                    for c in range(count-1,-1,-1):
                        if (data[c]['Id'] == 4660):
                            attack = attack + 1
                            break
                        # else:
                        	# print('NOT 4660')
                elif (re.search('Accesses:\\t\\tReadData', i['Message']) != None):
                    threat = threat + 1
                elif (re.search('Accesses:\\t\\tWriteData', i['Message']) != None):
                    attack = attack + 1
                else:
                	regular = regular + 1
            elif i['Id'] != 4660:
                regular = regular + 1
            count = count + 1
        #print(threat, attack, regular)
        # plt.show()

        axis = plt.subplot2grid((6,6),(0,0),rowspan = 6,colspan = 6)
        axis.pie([attack,threat,regular],colors = ['r', 'y', 'g'], startangle = 90, shadow = False, explode=[0.2, 0, 0])
        axis.set_title('Regular Vs Threat Vs Attack')
        axis.legend(['%s Attacks' % str(attack),'%s Threats' % str(threat),'%s Regular' % str(regular)])
        layout.addWidget(self.canvas, 1, 0)


        
        # scene = QGraphicsScene()
        # threat = analyse.AnalyseLogs.show_alert.threat
        # vbox = QVBoxLayout()
        # self.setLayout(vbox)
        # lbl = QLabel(threat)
        # vbox.addWidget(lbl)
        # scene = QGraphicsScene()
        # families = [1,2,3,4,5,6,7]
        # total = 0
        # colours = []
        # set_angle = 0
        # count1 = 0
        # total = sum(families)
        # for count in range(len(families)):
        #     number = []
        #     for count in range(3):
        #         number.append(random.randrange(0, 255))
        #     colours.append(QColor(number[0],number[1],number[2]))
        # for family in families:
        #     angle = round(family/total*16*360)
        #     ellipse = QGraphicsEllipseItem(0,0,400,400)
        #     ellipse.setPos(0,0)
        #     ellipse.setStartAngle(set_angle)
        #     ellipse.setSpanAngle(angle)
        #     ellipse.setBrush(colours[count1])
        #     set_angle += angle
        #     count1 +=1
        #     scene.addItem(ellipse)
        # view = QGraphicsView(scene)
        # view.show()


