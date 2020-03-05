# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'pkcs.ui'
#
# Created by: PyQt4 UI code generator 4.11.4
#
# WARNING! All changes made in this file will be lost!

from PyQt4 import QtCore, QtGui

try:
    _fromUtf8 = QtCore.QString.fromUtf8
except AttributeError:
    def _fromUtf8(s):
        return s

try:
    _encoding = QtGui.QApplication.UnicodeUTF8
    def _translate(context, text, disambig):
        return QtGui.QApplication.translate(context, text, disambig, _encoding)
except AttributeError:
    def _translate(context, text, disambig):
        return QtGui.QApplication.translate(context, text, disambig)

class Ui_PKCS(object):
    def setupUi(self, PKCS):
        PKCS.setObjectName(_fromUtf8("PKCS"))
        PKCS.resize(511, 456)
        self.label = QtGui.QLabel(PKCS)
        self.label.setGeometry(QtCore.QRect(10, 30, 141, 31))
        font = QtGui.QFont()
        font.setFamily(_fromUtf8("Adobe Caslon Pro Bold"))
        font.setPointSize(16)
        font.setBold(True)
        font.setWeight(75)
        self.label.setFont(font)
        self.label.setMouseTracking(False)
        self.label.setLayoutDirection(QtCore.Qt.LeftToRight)
        self.label.setFrameShape(QtGui.QFrame.NoFrame)
        self.label.setFrameShadow(QtGui.QFrame.Plain)
        self.label.setLineWidth(12)
        self.label.setMidLineWidth(9)
        self.label.setAlignment(QtCore.Qt.AlignCenter)
        self.label.setWordWrap(False)
        self.label.setObjectName(_fromUtf8("label"))
        self.frame = QtGui.QFrame(PKCS)
        self.frame.setGeometry(QtCore.QRect(20, 60, 461, 80))
        self.frame.setFrameShape(QtGui.QFrame.StyledPanel)
        self.frame.setFrameShadow(QtGui.QFrame.Plain)
        self.frame.setLineWidth(6)
        self.frame.setMidLineWidth(9)
        self.frame.setObjectName(_fromUtf8("frame"))
        self.radioButton = QtGui.QRadioButton(self.frame)
        self.radioButton.setGeometry(QtCore.QRect(20, 60, 90, 16))
        self.radioButton.setObjectName(_fromUtf8("radioButton"))
        self.radioButton_2 = QtGui.QRadioButton(self.frame)
        self.radioButton_2.setGeometry(QtCore.QRect(110, 60, 90, 16))
        self.radioButton_2.setObjectName(_fromUtf8("radioButton_2"))
        self.label_2 = QtGui.QLabel(PKCS)
        self.label_2.setGeometry(QtCore.QRect(10, 150, 141, 31))
        font = QtGui.QFont()
        font.setFamily(_fromUtf8("Adobe Caslon Pro Bold"))
        font.setPointSize(16)
        font.setBold(True)
        font.setWeight(75)
        self.label_2.setFont(font)
        self.label_2.setMouseTracking(False)
        self.label_2.setLayoutDirection(QtCore.Qt.LeftToRight)
        self.label_2.setFrameShape(QtGui.QFrame.NoFrame)
        self.label_2.setFrameShadow(QtGui.QFrame.Plain)
        self.label_2.setLineWidth(12)
        self.label_2.setMidLineWidth(9)
        self.label_2.setAlignment(QtCore.Qt.AlignCenter)
        self.label_2.setWordWrap(False)
        self.label_2.setObjectName(_fromUtf8("label_2"))
        self.listWidget = QtGui.QListWidget(PKCS)
        self.listWidget.setGeometry(QtCore.QRect(20, 180, 461, 171))
        self.listWidget.setObjectName(_fromUtf8("listWidget"))
        self.pushButton = QtGui.QPushButton(PKCS)
        self.pushButton.setGeometry(QtCore.QRect(20, 370, 131, 23))
        self.pushButton.setObjectName(_fromUtf8("pushButton"))
        self.pushButton_2 = QtGui.QPushButton(PKCS)
        self.pushButton_2.setGeometry(QtCore.QRect(20, 400, 131, 23))
        self.pushButton_2.setObjectName(_fromUtf8("pushButton_2"))
        self.frame.raise_()
        self.label.raise_()
        self.label_2.raise_()
        self.listWidget.raise_()
        self.pushButton.raise_()
        self.pushButton_2.raise_()

        self.retranslateUi(PKCS)
        QtCore.QMetaObject.connectSlotsByName(PKCS)

    def retranslateUi(self, PKCS):
        PKCS.setWindowTitle(_translate("PKCS", "KT Wiz Stick", None))
        self.label.setText(_translate("PKCS", "인증서 위치", None))
        self.radioButton.setText(_translate("PKCS", "하드디스크", None))
        self.radioButton_2.setText(_translate("PKCS", "WIz Stick", None))
        self.label_2.setText(_translate("PKCS", "인증서 선택", None))
        self.pushButton.setText(_translate("PKCS", "인증서 복사하기", None))
        self.pushButton_2.setText(_translate("PKCS", "인증서 삭제", None))

