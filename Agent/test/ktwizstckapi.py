# -*- coding: utf-8 -*-
import sys
import hashlib
import serial, struct, time, binascii, re, string, random
import serial.tools.list_ports
from Crypto.Cipher import AES
import base64
from binascii import hexlify
import re


serial_name = ''
serial_name_user = ''
serial_name_admin = ''



KEY = '0000000000000000000000000000000000000000000000000000000000000000'.decode('hex')
IV = '00000000000000000000000000000000'.decode('hex')

KEYadmin = '0000000000000000000000000000000000000000000000000000000000000000'.decode('hex')

g_msg ='' 
gui_mode = 158

msg = {
    0:u'정상 처리',
    100 : u'보안토큰이 연결되어 있지 않은 경우',
    101 : u'최대연결 오류(PC에 연결가능한 보안토큰 수 초과 오류)',
    102 : u'보안토큰이 PC에 인식되지 않아 연결 에러 발생',
    103 : u'USB 통신 오류',
    104 : u'카드 명령어 수행 에러',
    105 : u'BIO 인증 없이 카드 사용',

    131 : u'BIO 정보가 등록되지 않아 오류 발생',
    132 : u'BIO 센서 타임 아웃',
    133 : u'BIO 인증 실패 ',
    134 : u'BIO 인증 ID 없음',
    135 : u'BIO 센서 H/W 에러',
    136 : u'BIO 알고리즘 비정상 종료',
    
    141 : u'스마트카드 연결안됨',
    142 : u'스마트카드 APDU 인증 에러',
    
    27012 : u'PIN Lock 상태',
    25540 : u'PIN 인증 4회 남음',
    25539 : u'PIN 인증 3회 남음',
    25538 : u'PIN 인증 2회 남음',
    25537 : u'PIN 인증 1회 남음',
    25536 : u'PIN 인증 0회 남음',
    4000 : u'파라미터 값이 유효하지 않음',
    
    106 : u'관리자 인증 실패',
    107 : u'관리자 인증 없이 BIO 보안토큰 사용',
}

def setadmin():
    global serial_name_admin, KEYadmin
    ports = list(serial.tools.list_ports.comports()) 
    for port_no, description, address in ports:
        if address.find('2BE7:1513') > -1:
            serial_name_admin = port_no
            KEYadmin = setkey(serial_name_admin)
            return True
    return False

def set():
    global serial_name_user, KEY
    ports = list(serial.tools.list_ports.comports()) 
    for port_no, description, address in ports:
        if address.find('2BE7:1512') > -1:
            serial_name_user = port_no
            KEY = setkey(serial_name_user)
            return True
    return False
    
def setkey(serial_name):
    a = b'\xff\xff\xff\xff\xff'
    b = b'\x00'*112
    c = b'\x01'*16
    d =b+c
    baud_rate = 115200
    conn = serial.Serial(serial_name, baud_rate, timeout=5)
    conn.write(a+b+c)
    recv = conn.read(5)
    ciphertext = conn.read(128)
    KEY_tmp = hashlib.md5(d).digest()+hashlib.md5(d[0:16]).digest()
    IV_tmp = hashlib.md5(d[-16:]).digest()
    obj = AES.new(KEY_tmp, AES.MODE_CBC, IV_tmp)
    plan =  obj.decrypt(ciphertext)
    vvv =  hashlib.md5(plan[0:16]).digest()+plan[0:16]
    conn.close()
    return vvv

baud_rate = 115200
BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS) 
unpad = lambda s : s[0:-int(s[-1])]


        
def id_generator(size=6, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))

def Recv_data_paser(data):
    print('recv ',data)
    try:
        DATA = {}
        if len(data) > 0:
            seek = 0
            while True:
                Data_Tag = struct.unpack('<I', data[seek:seek + 4])[0]
                Len = struct.unpack('<I', data[seek + 4:seek + 8])[0]
                next_seek = seek + 8 + Len
                Value = data[seek + 8:next_seek]
                seek = next_seek
                DATA[Data_Tag] = Value
                if Len != len(Value):
                    raise NameError('Len != len(Value)')
                if len(data) == seek:
                    break
        else:
            DATA = None
        return DATA
    except Exception as e:
        print(e) 
        return False



def Data_pack(data):
    result = b''
    keylist = data.values()
    #keylist.sort()
    print(keylist)
    for a in keylist: 
        TAG = struct.pack('<I', a[0])
        # print '\t',a[0], a[2], [a[1]]
        if a[2] == 'N':
            VALUE = struct.pack('<I', a[1])
            # print '\t',a[0], a[2], [a[1]]
            #logger.debug("%s %s %s %s" % ('\t', a[0], a[2], [a[1]]))
        elif a[2] == 'S':
            VALUE = a[1]  # binascii.unhexlify(a[1].encode('hex'))
            #logger.debug("%s %s %s %s" % ('\t', a[0], a[2], [a[1]]))
        elif a[2] == 'B':
            print('b :', a[1].encode('utf8'))
            VALUE = a[1].encode('utf8')
            #logger.debug("%s %s %s %s" % ('\t', a[0], a[2], [binascii.hexlify(a[1])]))
        else:
            pass
        LEN = struct.pack('<I', len(VALUE))

        result += result
        result += TAG
        result += LEN
        result += VALUE
    return result        

def send_data2(cmd, data, serial_name, KEY, Sign_value_tmp = b'\x01', flag_ = False):
    
    print('send_data CMD :', cmd )

    PID = struct.pack('I', 136)+ struct.pack('I', 4)+struct.pack('I', 1)
    TID = struct.pack('I', 137)+ struct.pack('I', 4)+struct.pack('I', 1)
    
    if Sign_value_tmp != b'\x01':
        Sign_value = struct.pack('I', 134)+ struct.pack('I', len(Sign_value_tmp))+Sign_value_tmp
        data = bytes(data)+PID+TID+Sign_value
    else:
        data = bytes(data)+PID+TID
                    
    
    PLAINTEXT = struct.pack('B', cmd)+struct.pack('H', len(data))+data
    obj = AES.new(KEY, AES.MODE_CBC, IV)
    id = struct.pack('B', 64)
    CIPHERTEXT = obj.encrypt(sum_padding(PLAINTEXT, id))
    data_len = struct.pack('>I', len(CIPHERTEXT))
    send_data = id+data_len+CIPHERTEXT
    
    
    
    conn = serial.Serial(serial_name, baud_rate, timeout=5)
    ret = conn.write(send_data)
    print('send ', send_data )
    print('send_dat : len', ret)

    if flag_ == True:
        while True:
            data_a = b''
            while 5 > len(data_a):
                data = conn.read(1)
                data_a += data 
            Total_Len = struct.unpack('>I', data_a[1:5])[0]
            event = b''
            c_L = Total_Len
            while Total_Len > len(event):
                data = conn.read(c_L)
                event += data
                c_L = c_L - len(data)     
            
            obj = AES.new(KEY, AES.MODE_CBC, pc_tmp_dic[id])
            recv_data = unpad(obj.decrypt(event))
            if recv_data[0:3] == '\xff\xff\xff':
                print(recv_data[3:])
            else:
                conn.close()
                return Recv_data_paser(recv_data[3:])
                
            
            
        
    
    data_a = b''
    while 5 > len(data_a):
        data = conn.read(1)
        data_a += data 
        
    #data_a = conn.read(5)
    
    #print data_a.encode('hex')
    Total_Len = struct.unpack('>I', data_a[1:5])[0]
    #recv_data = conn.read()
    
    event = b''
    c_L = Total_Len
    #tt = 0
    while Total_Len > len(event):
        data = conn.read(c_L)
        event += data
        c_L = c_L - len(data)
    print(pc_tmp_dic)
    print("TOTAL_LEN :", Total_Len) 
    obj = AES.new(KEY, AES.MODE_CBC, pc_tmp_dic[id])
    recv_data = unpad(obj.decrypt(event))
    print(recv_data[0])
    print(recv_data[1:3])
    conn.close()
    #print recv_data[3:].encode('hex')
    return Recv_data_paser(recv_data[3:])
    #except Exception as e:
    #    print(e)
    #    set()
    #    return False
    
class wizstick():
    def __init__(self):
        self.count = 0
        self.hSession_value = 0
        self.aa = []
        self.serial_number = None
        self.comm_tmp_id = None
        self.pc_tmp_dic = {}
        self.tmp_data = None

    def add_padding_a(self,padding, data):
        #print(padding)
        #print(bytes(data))
        #print(struct.pack('B',padding)) 
        result_data = bytes(data)+bytes(id_generator(padding).encode('utf8'))+struct.pack('B',padding)
        return result_data

    def sum_padding(self,data, id):
        tt = struct.pack('q',int(time.time()))
        self.pc_tmp_dic[id] = tt+tt
        data = data+tt
        a,b = divmod(len(data),16)
        padding = 15-b
        if padding == 0:
            padding = 16
            return self.add_padding_a(padding, data)
        else:
            return self.add_padding_a(padding, data)

    def data_parser(self, data):
        tmp_data = data[3:]
        try:
            #logger.info(data.encode('hex'))
            DATA = {}
            if len(tmp_data) > 0:
                seek = 0
                while True:
                    Data_Tag = struct.unpack('<I', tmp_data[seek:seek + 4])[0]
                    Len = struct.unpack('<I', tmp_data[seek + 4:seek + 8])[0]
                    next_seek = seek + 8 + Len
                    Value = tmp_data[seek + 8:next_seek]
                    seek = next_seek
                    DATA[Data_Tag] = Value
                    if Len != len(Value):
                        raise NameError('Len != len(Value)')
                    if len(tmp_data) == seek:
                        break
            else:
                DATA = None
            return DATA
        except Exception as e:
            print(e) 
            return False

    def send_data(self, cmd, data, serial_name, KEY, Sign_value_tmp = b'\x01', flag_ = False, use_ddd=True, connection = None):

        conn = connection
        print('send_data CMD :', cmd, len(data) )
        PID = struct.pack('I', 136)+ struct.pack('I', 4)+struct.pack('I', 1)
        TID = struct.pack('I', 137)+ struct.pack('I', 4)+struct.pack('I', 1)
        
        if Sign_value_tmp != b'\x01':
            Sign_value = struct.pack('I', 134)+ struct.pack('I', len(Sign_value_tmp))+Sign_value_tmp
            data = bytes(data)+PID+TID+Sign_value
        else:
            data = bytes(data)+PID+TID
                        
        
        PLAINTEXT = struct.pack('B', cmd)+struct.pack('H', len(data))+data
        obj = AES.new(KEY, AES.MODE_CBC, IV)
        self.tmp_data = struct.pack('B', 64)
        CIPHERTEXT = obj.encrypt(self.sum_padding(PLAINTEXT, self.tmp_data ))
        data_len = struct.pack('>I', len(CIPHERTEXT))
        send_data = self.tmp_data +data_len+CIPHERTEXT
        print(self.pc_tmp_dic[self.tmp_data])
        ret = connection.write(send_data)

        return self.serial_recv(conn) 

    def serial_recv(self, conn):

        data_a = b''
        while 5 > len(data_a):
            data2 = conn.read(1)
            data_a += data2 
            
        Total_Len = struct.unpack('>I', data_a[1:5])[0]

        event = b''
        c_L = Total_Len
        #tt = 0
        while Total_Len > len(event):
            data2 = conn.read(c_L)
            event += data2
            c_L = c_L - len(data2)

        print(self.pc_tmp_dic[self.tmp_data])
        obj = AES.new(KEY, AES.MODE_CBC, self.pc_tmp_dic[self.tmp_data])
        recv_data = obj.decrypt(event)
        print("DECRYPT : ", recv_data)
        print("RECV LEN : ", len(event), len(recv_data))
        recv_data = unpad(recv_data)
        print("UNPAD : ", len(recv_data))

        
        return recv_data

     
    def print_list(self):
        for a in range(len(self.aa)) :
            #print self.aa.pop()
            pass
    
    def print_result(self, result):
        if result == False:
            print('print_result false')
            return

        try: 
            result_code = struct.unpack('<I', result[1])[0]
            if result_code in msg.keys():
                return (result_code, msg[result_code])
                #tmp_msg = 'Result : %s (%s)'%(str(result_code), msg[result_code])
                #self.aa.append(tmp_msg)
            else:
                tmp_msg = 'Result : Unkonw %s' %result_code
                return (result_code, 'Unkonw')
                #self.aa.append(tmp_msg)
        except Exception as e: 
            print('e :', e)

    
    def getSerial(self):
        conn = serial.Serial(serial_name_user, baud_rate, timeout=5)
        data = self.send_data(10, b'', serial_name_user, KEY, use_ddd=False, connection=conn)
        #data = self.serial_recv(conn)
        result = self.data_parser(data)

        self.serial_number = result[1]
        conn.close()
        return result

    def tmpCmd01(self):
        return
        #self.progressBar.setProperty("value", 0)
        data_ = struct.pack('<I', 1)+ struct.pack('<I', 4)+struct.pack('<I', 1)
        result = send_data(8, data_, serial_name_user, KEY)
        a = result[1]

        data = struct.pack('<I', 1)+ struct.pack('<I', len(a))+a
        result = send_data(9, data, serial_name_admin, KEYadmin)
        Sign_value_tmp = result[1]

        return (a,Sign_value_tmp)

    def tmpCmd02(self):
        print('tmpCmd02~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~')
        serial_num = self.serial_number
        ManageCode = b'TI'
        inBizNo = b'1111111119'
        inNationalID = b'1111111111111'
        regYN = b'01'
        compCD = b'KT_'
        CSN = serial_num
        keyID = b'01'
        deviceKey = b'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        data_ = struct.pack('<I', 1)+ struct.pack('<I', len(ManageCode))+ManageCode\
        +struct.pack('<I', 2)+ struct.pack('<I', len(inBizNo))+inBizNo\
        +struct.pack('<I', 3)+ struct.pack('<I', len(inNationalID))+inNationalID\
        +struct.pack('<I', 4)+ struct.pack('<I', len(regYN))+regYN\
        +struct.pack('<I', 5)+ struct.pack('<I', len(compCD))+compCD\
        +struct.pack('<I', 6)+ struct.pack('<I', len(CSN))+CSN\
        +struct.pack('<I', 7)+ struct.pack('<I', len(keyID))+keyID\
        +struct.pack('<I', 8)+ struct.pack('<I', len(deviceKey))+deviceKey
        print('ak###~~',data_)
        print('ak###~~',len(data_))

        result = send_data(8, data_, serial_name_user, KEY, use_ddd=False )
        a = result[1]
        self.print_result(result)
        print('result : ', result)
        data = struct.pack('<I', 1)+ struct.pack('<I', len(a))+a
        result = send_data(9, data, serial_name_admin, KEYadmin, use_ddd=False)
        #print result
        self.print_result(result)
        print('result : ', result)
        Sign_value_tmp = result[1]
        result = send_data(1, data_, serial_name_user, KEY, Sign_value_tmp, use_ddd=False )
        self.print_result(result)
        print('result : ', result)
        if chr( result[2][0] ) == '1':
            print('result @ == 1')
        else:
            print('result @ != 1')

    def bioRegister(self):
        id = b'7902191000228'
        ManageCode = b'RG'
        inBizNo = b'1111111119'
        inNationalID = id
        regYN = b'01'
        compCD = b'KT_'
        CSN = bytes(self.serial_number)
        keyID = b'01'
        deviceKey = b'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        User_number = struct.pack('<I', 1)
        finger_number = struct.pack('<I', 1)

        data_ = struct.pack('<I', 1)+ struct.pack('<I', len(ManageCode))+ManageCode\
        +struct.pack('<I', 2)+ struct.pack('<I', len(inBizNo))+inBizNo\
        +struct.pack('<I', 3)+ struct.pack('<I', len(inNationalID))+inNationalID\
        +struct.pack('<I', 4)+ struct.pack('<I', len(regYN))+regYN\
        +struct.pack('<I', 5)+ struct.pack('<I', len(compCD))+compCD\
        +struct.pack('<I', 6)+ struct.pack('<I', len(CSN))+CSN\
        +struct.pack('<I', 7)+ struct.pack('<I', len(keyID))+keyID\
        +struct.pack('<I', 8)+ struct.pack('<I', len(deviceKey))+deviceKey\
        +struct.pack('<I', 9)+ struct.pack('<I', 4)+User_number\
        +struct.pack('<I', 16)+ struct.pack('<I', 4)+finger_number

        conn_user = serial.Serial(serial_name_user, baud_rate, timeout=5)
        conn_admin = serial.Serial(serial_name_admin, baud_rate, timeout=5)

        #result = send_data2(8, data_, serial_name_user, KEY)
        data = self.send_data(8, data_, serial_name_user, KEY, connection=conn_user)
        #data = self.serial_recv(conn_user)
        print("DATA LEN",len(data))
        result = self.data_parser(data)
        a = result[1]

        print('~~~ : ' , a)

        data = struct.pack('<I', 1)+ struct.pack('<I', len(a))+a
        data = self.send_data(9, data, serial_name_admin, KEYadmin, connection=conn_admin)
        #data = self.serial_recv(conn_admin)
        print("DATA LEN",len(data))
        result = self.data_parser(data)
        Sign_value_tmp = result[1]

        #send_data2(1, data_, serial_name_user, KEY, Sign_value_tmp, flag_=True)
        data = self.send_data(1, data_, serial_name_user, KEY, Sign_value_tmp, connection=conn)
        return
        while True:
            print('while')
            if data[0:3] == b'\xff\xff\xff':
                print("PRCESSING....")
            else:
                print("COMPLETE")
                result = data_parser(data)
                break;




    def bioOpenin(self): 
        #self.aa.append('bioOpenin')
        result = send_data(240, b'', serial_name_user, KEY)

        tmp_result = self.print_result(result)
        if struct.unpack('<I', result[1])[0] == 0:
            tmp = struct.unpack('<I', result[2])[0]
        else:
            tmp = ''
        #self.aa.append('')
        #self.print_list()
        return (tmp_result, tmp)
            

    def bioCloseOut(self, ChID): 
        #self.aa.append('bioCloseOut')
        data = Data_pack({'hSession_value':[0x00000001, ChID, 'N']})
        result = send_data(241, data, serial_name_user, KEY)            
        tmp_result = self.print_result(result)
        return (tmp_result, '')
        #self.aa.append('')
        
    def bioLoginBioAuth(self, ChID):
        #self.aa.append('bioLoginBioAuth')
        data = Data_pack({'hSession_value':[0x00000001, ChID, 'N']})
        result = send_data(242, data, serial_name_user, KEY)
        tmp_result = self.print_result(result)
        return (tmp_result, '')
        #self.aa.append('') 
        #self.print_list()
        #return result
    
    def bioLoginSC(self, ChID, pin_number): 
        #self.aa.append('bioLoginSC')
        data = Data_pack({'hSession_value':[0x00000001, ChID, 'N'], 'PIN':[0x00000002, str(pin_number), 'B']})
        result = send_data(243, data, serial_name_user, KEY)
        tmp_result =  self.print_result(result)
        return (tmp_result, '')
        #self.aa.append('')
        #self.print_list()
        
    def bioLogoutSC(self, ChID):
        #self.aa.append('bioLogoutSC')
        data = Data_pack({'hSession_value':[0x00000001, self.hSession_value, 'N']})
        result = send_data(255, data, serial_name_user, KEY)
        tmp_result =  self.print_result(result)
        return (tmp_result, '')
        #self.aa.append('')
    
    def bioGetTokenInfo(self,ChID, Division):
        tmp_msg = {
             '\x00' : u'없음',
            '\x01' : u'서명용 범용',
            '\x02' : u'서명용 용도제한(은행,보험,신용카드)',
            '\x03' : u'서명용 용도제한(조달청)',
            '\x04' : u'서명용 용도제한(증권,보험)',
            '\x05' : u'키분배용 범용',}
                    
        #self.aa.append('bioGetTokenInfo')
        #self.aa.append(self.cb6.currentText())
        result_list = []
        #Division = int(str(self.cb6.currentIndex()))+1 #1 #inBizNo
        #Division = 2 #inNationalID
        data = Data_pack({'hSession_value':[0x00000001, ChID, 'N'], 'Division':[0x00000002, Division, 'N']})
        result = send_data(244, data, serial_name_user, KEY)
        tmp_result = self.print_result(result)
        
        if struct.unpack('<I', result[1])[0] == 0:
            #self.aa.append(result[2].encode('hex'))
            cert_num = struct.unpack('B', result[2][0])[0]
            #self.aa.append(u'저장된 인증서 개수 : %s'%cert_num)
            #result_list.append(cert_num)
            for a in range(1, 5):
                #self.aa.append(str(a)+' : '+tmp_msg[result[2][a]])
                result_list.append(result[2][a])
        #self.aa.append('')
        #self.print_list()
        return (tmp_result, result_list)
        
    def bioGetCertificate(self,ChID,  Division, CertIndex):
        #self.aa.append('bioGetCertificate')
        #Division = int(str(self.cb7.currentIndex()))+1
        #CertIndex = int(str(self.cb7_a.currentIndex()))+1
        data = Data_pack({'hSession_value':[0x00000001, ChID, 'N'], 'Division':[0x00000002, Division, 'N'], 'CertIndex':[0x00000003, CertIndex, 'N']})
        result = send_data(245, data, serial_name_user, KEY)
        tmp_result = self.print_result(result)
        if struct.unpack('<I', result[1])[0] == 0:
            #self.aa.append('Certificate : %s'%result[2].encode('hex')) 
            #self.aa.append('Certificate : ') 
            #x509_print(result[2], self.aa)
            tmp = result[2]
        else:
            tmp = ''
        #self.aa.append('')
        #self.print_list()
        return (tmp_result, tmp)
        
    def bioGetRandom(self, ChID, Division, CertIndex):
        #self.aa.append('bioGetRandom')
        #Division = int(str(self.cb8.currentIndex()))+1
        #CertIndex = int(str(self.cb8_a.currentIndex()))+1     
        data = Data_pack({'hSession_value':[0x00000001, ChID, 'N'], 'Division':[0x00000002, Division, 'N'], 'CertIndex':[0x00000003, CertIndex, 'N']})
        result = send_data(246, data, serial_name_user, KEY)
        tmp_result = self.print_result(result)
        if struct.unpack('<I', result[1])[0] == 0:
            #self.aa.append('R : %s'%result[2].encode('hex'))
            tmp = result[2]
        else:
            tmp = ''
        #self.aa.append('')
        #self.print_list()
        return (tmp_result, tmp)
        
    def bioGetSign(self, ChID, Division, CertIndex, InData):
        #self.aa.append('bioGetSign')
        #Division = int(str(self.cb9.currentIndex()))+1
        #CertIndex = int(str(self.cb9_a.currentIndex()))+1      
        #InData = '\x01'*256
        data = Data_pack({'hSession_value':[0x00000001, ChID, 'N'], 'Division':[0x00000002, Division, 'N'], 'CertIndex':[0x00000003, CertIndex, 'N'], 'InData':[0x00000004, InData, 'B']})
        result = send_data(247, data, serial_name_user, KEY)
        tmp_result = self.print_result(result)
        if struct.unpack('<I', result[1])[0] == 0:
            #self.De_Indata = result[2]
            #self.aa.append('InData : %s'%InData.encode('hex'))
            #self.aa.append('Signature : %s'%result[2].encode('hex'))
            tmp = result[2]
        else:
            tmp = ''
        #self.aa.append('')
        #self.print_list()
        return (tmp_result, tmp)
    
    def bioRSAPriDec(self, ChID, Division, CertIndex, InData):
       
        #self.aa.append('bioRSAPriDec')
        #Division = int(str(self.cb10.currentIndex()))+1
        #CertIndex = int(str(self.cb10_a.currentIndex()))+1        
        #InData = '\x01'*256
        
        data = Data_pack({'hSession_value':[0x00000001, ChID, 'N'], 'Division':[0x00000002, Division, 'N'], 'CertIndex':[0x00000003, CertIndex, 'N'], 'InData':[0x00000004, InData, 'B']})
        #print data
        result = send_data(248, data, serial_name_user, KEY)
        tmp_result = self.print_result(result)
        if struct.unpack('<I', result[1])[0] == 0:
            #self.aa.append('InData : %s'%InData.encode('hex'))
            #self.aa.append('DecData : %s'%result[2].encode('hex'))
            tmp = result[2]
        else:
            tmp = ''
        #self.aa.append('')
        return (tmp_result, tmp)
    
    def bioGetIDN(self, ChID,Division):
        self.aa.append('bioGetIDN')
        #Division = int(str(self.cb11.currentIndex()))+1    
        data = Data_pack({'hSession_value':[0x00000001, ChID, 'N'], 'Division':[0x00000002, Division, 'N']})
        result = send_data(249, data, serial_name_user, KEY)
        tmp_result = self.print_result(result)
        if struct.unpack('<I', result[1])[0] == 0:
            #self.aa.append('IDN : %s'%result[2])
            tmp = result[2]
        else:
            tmp = ''
        #self.aa.append('')
        return (tmp_result, tmp)
        
        
    
    def bioGetCSN(self, ChID):
        self.aa.append('bioGetCSN')
        data = Data_pack({'hSession_value':[0x00000001, ChID, 'N']})
        result = send_data(250, data, serial_name_user, KEY)
        tmp_result = self.print_result(result)
        if struct.unpack('<I', result[1])[0] == 0:
            #self.aa.append('CSN : %s'%result[2].encode('hex'))
            #self.aa.append('')
            tmp = result[2].encode('hex')
        else:
            tmp = ''
        return (tmp_result, tmp)
    
    def bioGenDevAuth(self,ChID):
        #self.aa.append('bioGenDevAuth')
        auth_random = '\x00'*16   
        data = Data_pack({'hSession_value':[0x00000001, ChID, 'N'], 'KeyID':[0x00000002, 1, 'N'], 'auth_random':[0x00000003, auth_random, 'B'], 'RandomLen':[0x00000004, len(auth_random), 'N']})
        result = send_data(251, data, serial_name_user, KEY)
        tmp_result = self.print_result(result)
        if struct.unpack('<I', result[1])[0] == 0:
            #self.aa.append('auth_random : %s'%auth_random.encode('hex'))
            #self.aa.append('pDevAuth : %s'%result[2].encode('hex'))
            tmp = result[2]
        else:
            tmp = ''
        return (tmp_result, tmp)            
        #self.aa.append('')
    
    def bioGetManufacture(self, ChID):
        #self.aa.append('bioGetManufacture')
        #Division = 1    
        data = Data_pack({'hSession_value':[0x00000001, ChID, 'N']})
        result = send_data(252, data, serial_name_user, KEY)
        tmp_result = self.print_result(result)
        if struct.unpack('<I', result[1])[0] == 0:
            #self.aa.append('Manufacture : %s'%result[2])
            tmp = result[2]
        else:
            tmp = ''
        return (tmp_result, tmp)
    
    def bioGetUserID(self):
        #self.aa.append('bioGetUserID')
        #Division = 1
        #data = Data_pack({'hSession_value':[0x00000001, self.hSession_value, 'N']})
        data = ''
        result = send_data(253, data, serial_name_user, KEY)
        tmp_result = self.print_result(result)
        if struct.unpack('<I', result[1])[0] == 0:
            #self.aa.append('UserID : %s'% struct.unpack('<L', result[2])[0])
            tmp = result[2]
        else:
            tmp = ''
        return (tmp_result, tmp)
    
    def bioSetUserID(self, ChID):
        #self.aa.append('bioSetUserID')
        data = Data_pack({'hSession_value':[0x00000001, ChID, 'N']})
        result = send_data(254, data, serial_name_user, KEY)
        tmp_result = self.print_result(result)
        return (tmp_result, '')
        
    def logdel(self):
        self.aa.clear()
       
if __name__ == '__main__':
    set()
    setadmin()
    tmp = wizstick()
    print( "SERIAL : ", tmp.getSerial() )
    #print( "TMP01 : ", tmp.tmpCmd01() )
    #print( "TMP02 : ", tmp.tmpCmd02() )
    #print( "reg : ", tmp.bioRegister() )
    #print( tmp.bioOpenin() )
    #print( tmp.bioLoginBioAuth( 0 ) )
    #print( tmp.bioLoginSC( 0, '00000000') )
    #print( tmp.bioGetTokenInfo(2,1) )
    #data = tmp.bioGetCertificate(2, 1)
    #tmp.bioGetRandom(2, 1)
    #tmp.bioGetSign(2,1,'A'*256)
    #tmp.bioLogoutSC()
    #tmp.bioCloseOut()
    '''
    from Crypto.Cipher import PKCS1_v1_5
    from Crypto.PublicKey import RSA
    from Crypto.Util.number import bytes_to_long, long_to_bytes
    
    x509cert = x509_parse(data)
    tbs = x509cert.tbsCertificate
    algType = tbs.pub_key_info.algType
    algParams = tbs.pub_key_info.key
    
    e = long(algParams["exp"])
    n = bytes_to_long(algParams["mod"])
    print(e)
    print n
 
    keyPub = RSA.construct((n, e))
    tmp_a = keyPub.encrypt('A'*256, 'x')[0]
    
    print [tmp_a]
    
    print tmp.bioRSAPriDec(2,1,tmp_a)
    '''