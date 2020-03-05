# -*- coding: utf-8 -*-
from PyQt4.QtGui import *
import pkcs
import sys
import toolkit_py
import testp
import binascii
from binascii import unhexlify
import struct


class XDialog(QDialog, pkcs.Ui_PKCS):
    def __init__(self):
        QDialog.__init__(self)
        self.setupUi(self)
 
        self.radioButton.clicked.connect(self.harddisk)
        self.radioButton_2.clicked.connect(self.wizstick)
        self.pushButton.clicked.connect(self.pkcs_copy)
        self.pushButton_2.clicked.connect(self.pkcs_del)
        
        self.pushButton.setEnabled(False)
        self.pushButton_2.setEnabled(False)
        self.cert_dic ={}
        self.wiz_cert_dic ={}
        #print toolkit_py.FP_VERIFY('KT_WZS_KEY_USAGE_SIGN')[0].encode('hex')
        #self.listWidget.setSelectionMode(QAbstractItemView.ExtendedSelection)
        
    def harddisk(self):
        #self.listWidget
        self.pushButton_2.setEnabled(False)
        
        self.listWidget.clear()
        self.cert_dic.clear()
        result = toolkit_py.get_cert_list()
        count = 0
        if len(result.keys()) > 0:
            self.pushButton.setEnabled(True)
        
        for a in result.keys():
            
            #tmp = "%s\\%s" %(result[a][0],result[a][1])
      
            #aaa = tmp.decode('cp949')
            self.cert_dic[count] = [result[a][0],result[a][1]]
            tmp_path = result[a][0]
            #print tmp_path
            count = count +1
            a = testp.PinkSign()
            a.load_pubkey(pubkey_path=tmp_path+"\\"+"signCert.der")
            #print a.dn()[-1], a.valid_date()[1]
            for b in a.dn():
                print b
            print "===="
            tmp = "%s \t %s" %(a.valid_date()[1], a.dn()[-1])
            aaa = tmp.decode('utf-8')
            item = QListWidgetItem(aaa)
            self.listWidget.addItem(item)
            
        #QMessageBox.information(self, "", "")
 
    def wizstick(self):
        
        self.pushButton.setEnabled(False)
        self.listWidget.clear()
        result = toolkit_py.ATTR_GET('00000000', 'KT_WZS_ATTR_CONTAINER_CONT')
        print result.encode('hex')
        #cmd, lh = stunpack('<Bh',recv_data_b[0:3])
        #print int(result[3:])
        self.wiz_cert_dic.clear()
        
        num = struct.unpack('>i',result)[0]
        if num > 0:
            self.pushButton_2.setEnabled(True)        
        for a in range(num):#int(result[6:])
            #print a+1
            tmp = '{0:02d}'.format(a+1)
            recv_data_b = toolkit_py.ATTR_GET(tmp+'000000', 'KT_WZS_ATTR_CERT_LIST')
            #recv_data_b = binascii.unhexlify(recv_data_b)
            #recv_data = recv_data_b[3:]
            recv_data =  recv_data_b
            #print recv_data.encode('hex')
            try:
                index_count = 0
                index_tmp = []
                #print recv_data
                for c in recv_data:
                    if c == '$':
                       index_tmp.append(index_count)
                    index_count = index_count + 1
                
                #print index_tmp
                
                UUID = recv_data[0:index_tmp[0]]#recv_data[0:36]
                #print UUID.encode('hex')
                SKI = recv_data[index_tmp[0]+1:index_tmp[1]]#recv_data[37:57].encode('hex')
                cert = recv_data[index_tmp[1]+1:]#recv_data[58:].encode('hex')
                #print UUID, SKI[0:4].encode('hex')
                #print a
                self.wiz_cert_dic[a] = [SKI[0:4],UUID]
                #print self.wiz_cert_dic[a]
                #print cert.encode('hex')
                a = testp.PinkSign()
                a.load_pubkey(pubkey_data=cert)
                
                #print a.dn()[-1], a.valid_date()[1]
                
                
                tmp = "%s \t %s" %(a.valid_date()[1], a.dn()[-1])
                aaa = tmp.decode('utf-8')
                item = QListWidgetItem(aaa)
                self.listWidget.addItem(item)
            except Exception, e:
                print e
            
            
        
        #for i in range(10):
            #i = i +10
            #item = QListWidgetItem("Item %i" % i)
            #self.listWidget.addItem(item)
        #QMessageBox.information(self, "", "")

    def pkcs_copy(self):
        
        #self.label2 = QtGui.QLabel(PKCS2)
        #editor = QLineEdit()
        #editor.setEchoMode(QLineEdit.Password)
        #editor.show()
        text, ok = QInputDialog.getText(self, u'인증서 복사', u'인증서 패스워드 입력', mode=QLineEdit.Password)
        #le.setEchoMode(QInputDialog.Password)
        QMessageBox.information(self, u"인증서 관리", u"지문 인증 시작")
        if toolkit_py.FP_VERIFY('KT_WZS_KEY_USAGE_SIGN')[0].encode('hex') == '01':
            if ok and len(text) < 30:
                #print str(text)
                #self.le1.setText(str(text))
                #print self.listWidget.selectedItems()
                #print self.listWidget.currentRow()
                #print self.cert_dic[self.listWidget.currentRow()]
                try:
                    hHnd = self.send_SignPri(self.cert_dic[self.listWidget.currentRow()][0], str(text))
                    #print "aaaa", hHnd.encode('hex')
                    text = 'A'*30
                    text = ''
                    with open(self.cert_dic[self.listWidget.currentRow()][0]+'\\'+self.cert_dic[self.listWidget.currentRow()][1], 'rb') as f:
                        data = f.read()
                        #print data.encode('hex')
                    #print hHnd.encode('hex')
                    self.ATTR_SET(hHnd, 'KT_WZS_ATTR_CERT', data.encode('hex'))
                    QMessageBox.information(self, u"인증서 관리", u"인증서 복사가 완료되었습니다.")
                except Exception, e:
                    print e
                    QMessageBox.information(self, u"인증서 관리", u"패스워드가 일치 하지 않습니다.")
            else:
                QMessageBox.information(self, u"인증서 관리", u"복사에 실패 하였습니다.")
    
    def pkcs_del(self):
        #print self.wiz_cert_dic
        QMessageBox.information(self, u"인증서 관리", u"지문 인증 시작")
        if toolkit_py.FP_VERIFY('KT_WZS_KEY_USAGE_SIGN')[0].encode('hex') == '01':
            hHnd = self.wiz_cert_dic[self.listWidget.currentRow()][0]
            if toolkit_py.PUB_DEL(hHnd).encode('hex') == '01':
                QMessageBox.information(self, u"인증서 관리", u"인증서를 삭제하였습니다.")
                self.wizstick()
        
    def send_SignPri(self, path, passwd):
        result, r = toolkit_py.SignPri_send(path, passwd)
        #print result.encode('hex'), r
        #print result[6:16], format(r, 'x')
        hHnd = result #int(hHnd, 16)
        self.ATTR_SET(hHnd, 'KT_WZS_ATTR_KVID_R', format(r, 'x'))
        return hHnd
        
    def ATTR_SET(self, hHnd, ATTR, data):
        if toolkit_py.ATTR_SET(hHnd, ATTR, data).encode('hex') == '01':
            pass
        else:
            QMessageBox.information(self, u"인증서 관리", u"속성 저장에 실패 하였습니다.")
    
app = QApplication(sys.argv)
dlg = XDialog()
dlg.show()
app.exec_()