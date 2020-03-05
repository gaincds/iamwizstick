#-*- coding: utf-8 -*-

import socket
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5 as PKCS1_v1_5_sign 
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Cipher import AES
import hmac
import wiztoken_UI as wiztoken
import os, time, json, struct
import hashlib
import random
import pybase64
import proxy_agent2
import subprocess
import threading
from asn1crypto.x509 import Certificate
import cStringIO

#from asn1crypto.crl import 

OIDlist = {
       # 1 법인, 2 개인
       # 1 서명용 범용 , 2 서명용 용도제한, 3 서명용 용도 제한(조달청용), 4 서명용 용도 제한 증권 보험 5 키분배용  
       '1.2.410.200004.5.2.1.1':[u'한국정보인증',u'법인 범용',1,1], 
       '1.2.410.200004.5.1.1.7':[u'한국증권전산',u'법인 범용',1,1],
       '1.2.410.200005.1.1.5':[u'금융결제원',u'법인 범용',1,1],
       '1.2.410.200004.5.4.1.2':[u'한국전자인증',u'법인 범용',1,1],
       '1.2.410.200012.1.1.3':[u'한국무역정보통신',u'법인 범용',1,1],
       '1.2.410.200004.5.2.1.3':[u'한국정보인증',u'조달청 내부',3,3],
       '1.2.410.200004.5.2.1.2':[u'한국정보인증',u'개인 범용',2,1],
       '1.2.410.200004.5.1.1.5':[u'한국증권전산',u'개인 범용',2,1],
       '1.2.410.200004.5.1.9.2':[u'한국증권전산',u'개인신용카드',2,2],
       '1.2.410.200005.1.1.1':[u'금융결제원',u'개인 범용',2,1],
       '1.2.410.200005.1.1.6.2':[u'금융결제원',u'개인신용카드',2,2],
       '1.2.410.200004.5.3.1.9':[u'한국정보사회진흥원',u'개인 범용',2,1],
       '1.2.410.200004.5.4.1.1':[u'한국전자인증',u'개인 범용',2,1],
       '1.2.410.200012.1.1.1':[u'한국무역정보통신',u'개인 범용',2,1],
       '1.2.410.200004.5.2.1.7.1':[u'한국정보인증',u'은행거래용/보험용',2,4],
       '1.2.410.200005.1.1.4':[u'금융결제원',u'은행/보험용',2,2],
       '1.2.410.200004.5.4.1.101':[u'한국전자인증',u'인터넷뱅킹용',2,2],
       '1.2.410.200004.5.4.1.102':[u'한국전자인증',u'증권거래용',2,4],
       '1.2.410.200004.5.4.1.103':[u'한국전자인증',u'개인신용카드',2,2],
       '1.2.410.200012.1.1.101':[u'한국무역정보통신',u'개인은행/보험용',2,2],
       '1.2.410.200012.1.1.103':[u'한국무역정보통신',u'개인증권/보험용',2,2],
       '1.2.410.200012.1.1.105':[u'한국무역정보통신',u'개인신용카드',2,2],
       '1.2.410.200004.5.2.1.7.2':[u'한국정보인증',u'개인증권/보험용',2,4],
       '1.2.410.200004.5.1.1.9':[u'한국증권전산',u'개인증권/보험용',2,4],
       '1.2.410.200004.5.2.1.7.3':[u'한국정보인증',u'개인신용카드',2,2]      
       }
    
wiz_stick = wiztoken.wizstick()
BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS) 
unpad = lambda s : s[:-ord(s[len(s)-1:])]

def wizstick_cert_view(GWIP, Division, PIN, GWPORT):
    # TokenInfo 1 biz 2nat
    if wiztoken.set() == False:
        return (False, '', '','','','','')    
    
    result, ChID = wiz_stick.bioOpenin()
    if result[0] != 0:
        return (result, '', '','','','','')    
    
    result, wiz_data = wiz_stick.bioLoginBioAuth(ChID)
    if result[0] != 0:
        return (result, '', '','','','','')       
    
    result, CSN = wiz_stick.bioGetCSN(ChID)
    if result[0] != 0:
        return (result, '', '','','','','')      
        
    result, wiz_data = wiz_stick.bioLoginSC(ChID, PIN)
    if result[0] != 0:
        return (result, '', '','','','','')       
    
    cert_list = {}
    certindex = ''
    cert_infor = {}
    indexcount = 1
    result, CERT_LIST = wiz_stick.bioGetTokenInfo(ChID, Division)
    if result[0] != 0:
        return (result, '', '','','','','')     

    if '\x01' in CERT_LIST:
        cert_policy_identifier = '\x01'
    elif '\x02' in CERT_LIST:
        cert_policy_identifier = '\x02'
    elif '\x03' in CERT_LIST:
        cert_policy_identifier = '\x03'
    elif '\x04' in CERT_LIST:
        cert_policy_identifier = '\x04'
    else:
        return ((997, u'서명가능한 인증서가 존재하지 않습니다.'), '', '','','','','')      
        
    for i in CERT_LIST: #biz
        if i == cert_policy_identifier:
            result, data = wiz_stick.bioGetCertificate(ChID, Division, indexcount)
            if result[0] != 0:
                return (result, '', '','','','','')                
            #x509cert = wiztoken.x509_parse(data)
            #tbs = x509cert.tbsCertificate
            #print '1'+str(indexcount), "%s ~ %s Issuer: %s, Subject: %s"%( tbs.validity.get_valid_from_as_datetime(), tbs.validity.get_valid_to_as_datetime(), tbs.issuer, tbs.subject)
            cert = Certificate.load(data)
            cert.ocsp_urls
            validity = cert['tbs_certificate']['validity'].native['not_after']
            subject =  cert['tbs_certificate']['subject'].native['common_name']
            issuer = cert['tbs_certificate']['issuer'].native['common_name']
            policy_identifier = OIDlist[cert._certificate_policies_value.native[0]['policy_identifier']][1]
            CRL = cert._crl_distribution_points_value.native[0]['distribution_point'][0]
            #print str(TokenInfo)+str(indexcount), validity, subject, issuer, policy_identifier    
            cert_infor[str(Division)+str(indexcount)] = (validity, subject, issuer, policy_identifier, CRL)
            cert_list[str(Division)+str(indexcount)] =  data
            certindex = str(Division)+str(indexcount)
        indexcount = indexcount+1    
    
    #certindex = raw_input('Cert chioce : ')
    
    result, IDN = wiz_stick.bioGetIDN(ChID, Division)
    if result[0] != 0:
        return (result, '', '','','','','')       
    IDN = hashlib.sha1(IDN).hexdigest()
    
    #with open('CRL.der', 'wb') as f:
        #f.write(pybase64.standard_b64encode(cert_list[str(certindex)]))
    
    msg = json.dumps({'Time':time.time(), 'IDN':IDN ,'CSN':CSN, 'Cert':pybase64.standard_b64encode(cert_list[str(certindex)])})
    #print u'사용자 등록을 위해 필요한 원본 데이터(json 형식) = msg'
    #print ' ->',msg
    Indata = hashlib.sha256(msg).digest()
    #print u'msg 값을 sha256 hash 적용 한 값 = Indata'
    #print ' ->', Indata.encode('hex')
    
    result, Sign_data = wiz_stick.bioGetSign(ChID, int(certindex[0]), int(certindex[1]), Indata)
    if result[0] != 0:
        return (result, '', '','','','','')         
    
    #print u'Indata 값을 wizstick api 이용하여 서명 요청하여 전달 받은 서명 값 = Sign_data'
    #print ' ->', Sign_data.encode('hex')
    list_data = json.dumps({'msg':msg, 'msg_hash':pybase64.standard_b64encode(Indata), 'Sign_data':pybase64.standard_b64encode(Sign_data)})
    #print u'GW 접속 가능 리스트를 받기위한 최종 데이터 (json 형식)  = list_data'
    #print ' ->', list_data
    
    result, wiz_data = wiz_stick.bioCloseOut(ChID)
    if result[0] != 0:
        return (result, '', '','','','','')    
    
    #print u'접속 가능 리스트 수신'
    try:
        recv_data = Send_Data(GWIP, 'List', list_data, GWPORT)
        if recv_data[0] == False:
            return ((999, u'GW 서버 통신 실패'), '', '','','','','')    
    except Exception, e:
        return ((998, str(recv_data)), '', '','','','','')
        
    return (True, CSN, cert_list[str(certindex)], certindex, IDN, cert_infor[str(certindex)], recv_data[1])

def regapi(GWIP, Division, PIN, User_ID, Email, Name, Phone_number, ORG, GWPORT):
    #print GWIP, Division, PIN, User_ID, Email, Name, Phone_number, ORG
    #User_ID = raw_input('ID : ')
    #Email = raw_input('E-mail : ')
    #Name = raw_input('Name : ')
    #Phone_number = raw_input('phone number : ')
    #ORG= raw_input('ORG : ')
    
    if wiztoken.set() == False:
        return (False, '', '','')    
    
    result, ChID = wiz_stick.bioOpenin()
    if result[0] != 0:
        return (result, '', '','')    
    
    result, wiz_data = wiz_stick.bioLoginBioAuth(ChID)
    if result[0] != 0:
        return (result, '', '','')          
    
    result, CSN = wiz_stick.bioGetCSN(ChID)
    if result[0] != 0:
        return (result, '', '','')         
        
    result, wiz_data = wiz_stick.bioLoginSC(ChID, PIN)
    if result[0] != 0:
        return (result, '', '','')          
    
    cert_list = {}
    certindex = ''
    cert_infor = {}
    indexcount = 1
    result, CERT_LIST = wiz_stick.bioGetTokenInfo(ChID, Division)
    if result[0] != 0:
        return (result, '', '','')       
    
    
    if '\x01' in CERT_LIST:
        cert_policy_identifier = '\x01'
    elif '\x02' in CERT_LIST:
        cert_policy_identifier = '\x02'
    elif '\x03' in CERT_LIST:
        cert_policy_identifier = '\x03'
    elif '\x04' in CERT_LIST:
        cert_policy_identifier = '\x04'
    else:
        return ((997, u'서명가능한 인증서가 존재하지 않습니다.'), '', '','')  
        
    for i in CERT_LIST: #biz
        if i == cert_policy_identifier:
            result, data = wiz_stick.bioGetCertificate(ChID, Division, indexcount)
            if result[0] != 0:
                return (result, '', '','')                   
            #x509cert = wiztoken.x509_parse(data)
            #tbs = x509cert.tbsCertificate
            #print '1'+str(indexcount), "%s ~ %s Issuer: %s, Subject: %s"%( tbs.validity.get_valid_from_as_datetime(), tbs.validity.get_valid_to_as_datetime(), tbs.issuer, tbs.subject)
            cert = Certificate.load(data)
            cert.ocsp_urls
            validity = cert['tbs_certificate']['validity'].native['not_after']
            subject =  cert['tbs_certificate']['subject'].native['common_name']
            issuer = cert['tbs_certificate']['issuer'].native['common_name']
            policy_identifier = OIDlist[cert._certificate_policies_value.native[0]['policy_identifier']][1]
            CRL = cert._crl_distribution_points_value.native[0]['distribution_point'][0]
            #print str(TokenInfo)+str(indexcount), validity, subject, issuer, policy_identifier    
            cert_infor[str(Division)+str(indexcount)] = (validity, subject, issuer, policy_identifier, CRL)
            cert_list[str(Division)+str(indexcount)] =  data
            certindex = str(Division)+str(indexcount)
        indexcount = indexcount+1    
    
    #certindex = raw_input('Cert chioce : ')
    
    result, IDN = wiz_stick.bioGetIDN(ChID, Division)
    if result[0] != 0:
        return (result, '', '','')         
    IDN = hashlib.sha1(IDN).hexdigest()    
    
    #print certindex
    #print cert_list
    
    #print {'Time':time.time(), 'User_ID':User_ID, 'Email':Email, 'Name':Name, 'Phone_number':Phone_number, 'ORG':ORG, 'IDN':IDN ,'CSN':CSN, 'Cert':pybase64.standard_b64encode(cert_list[str(certindex)])}
    msg = json.dumps({'Time':time.time(), 'User_ID':User_ID, 'Email':Email, 'Name':Name, 'Phone_number':Phone_number, 'ORG':ORG, 'IDN':IDN ,'CSN':CSN, 'Cert':pybase64.standard_b64encode(cert_list[str(certindex)])})
    #print u'사용자 등록을 위해 필요한 원본 데이터(json 형식) = msg'
    #print ' ->',msg
    
    Indata = hashlib.sha256(msg).digest()
    #print u'msg 값을 sha256 hash 적용 한 값 = Indata'
    #print ' ->', Indata.encode('hex')
    
    result, Sign_data = wiz_stick.bioGetSign(ChID, int(certindex[0]), int(certindex[1]), Indata)
    if result[0] != 0:
        return (result, '', '','')       
    #print u'Indata 값을 wizstick api 이용하여 서명 요청하여 전달 받은 서명 값 = Sign_data'
    #print ' ->', Sign_data.encode('hex')
    
    reg_data = json.dumps({'msg':msg, 'msg_hash':pybase64.standard_b64encode(Indata), 'Sign_data':pybase64.standard_b64encode(Sign_data)})
    #print u'GW 서버로 등록요청을 위해 전달해야되는 최종 데이터 (json 형식)  = reg_data'
    #print ' ->', reg_data
    
    result, wiz_data = wiz_stick.bioCloseOut(ChID)
    if result[0] != 0:
        return (result, '', '','')      
    
    try:
        recv_data = Send_Data(GWIP, 'REG', reg_data, GWPORT)
        #print recv_data
        if recv_data[0] == False:
            return ((999, u'GW 서버 통신 실패'), '', '','')  
    except Exception, e:
        return ((998, str(recv_data)), "", "", "")
        
    return (True, CSN, cert_infor[str(certindex)], recv_data[1])  
            
def auth(GWIP, CSN, Cert, Certindex, IDN, PIN, EQP_UID, GWPORT):
    if wiztoken.set() == False:
        return (False,  '', '','','')  
    
    result, ChID = wiz_stick.bioOpenin()
    if result[0] != 0:
        return (result,  '', '','','')  
    
    result, wiz_data = wiz_stick.bioLoginBioAuth(ChID)
    if result[0] != 0:
        return (result,  '', '','','')     
    
    result, wiz_data = wiz_stick.bioLoginSC(ChID, PIN)
    if result[0] != 0:
        return (result,  '', '','','')   
    
    msg = json.dumps({'Time':time.time(), 'IDN':IDN ,'CSN':CSN, 'EQP_UID':EQP_UID,'Cert':pybase64.standard_b64encode(Cert)})
    #print u'사용자 등록을 위해 필요한 원본 데이터(json 형식) = msg'
    #print ' ->',msg
    
    Indata = hashlib.sha256(msg).digest()
    #print u'msg 값을 sha256 hash 적용 한 값 = Indata'
    #print ' ->', Indata.encode('hex')
    
    result, Sign_data = wiz_stick.bioGetSign(ChID, int(Certindex[0]), int(Certindex[1]), Indata)
    if result[0] != 0:
        return (result,  '', '','','')  
    
    #print u'Indata 값을 wizstick api 이용하여 서명 요청하여 전달 받은 서명 값 = Sign_data'
    #print ' ->', Sign_data.encode('hex')
    
    auth_data = json.dumps({'msg':msg, 'msg_hash':pybase64.standard_b64encode(Indata), 'Sign_data':pybase64.standard_b64encode(Sign_data)})
    #print u'GW 서버로 등록요청을 위해 전달해야되는 최종 데이터 (json 형식)  = reg_data'
    #print ' ->', auth_data
    
    #print u'GW 서버로 데이터 전송'    
    try:
        recv_data = Send_Data(GWIP, 'Auth', auth_data, GWPORT)
        #print recv_data
        if recv_data[0] == False:
            return ((999, u'GW 서버 인증 실패'), '', '','','')    
    except Exception, e:
        return ((998, str(recv_data)), '', '','','')
    
    
    if recv_data[1]['result'] == 'False':
        return ((998, recv_data[1]['data']), '', '','','')
    
    #print u'GW 서버로 부터 수신받은 데이터를 Wiz Stick으로 전송하여 복호화하여 접속인증키 및 접속 포트 번호 획득'
    result, authkey = wiz_stick.bioRSAPriDec(ChID, int(Certindex[0]), int(Certindex[1]), pybase64.standard_b64decode(recv_data[1]['data']))
    if result[0] != 0:
        return (result, '', '','','')  
    #print recv_data['port']
    #print authkey
    result, wiz_data = wiz_stick.bioCloseOut(ChID)
    if result[0] != 0:
        return (result, '', '','','') 
    
    return (True, GWIP, int(recv_data[1]['port']), authkey, recv_data[1])

def randomword(length):
    return ''.join(random.choice("ZXCVBNM<>?ASDFGHJKL:QWERTYUIOP{}!@#$%^&*()_+zxcvbnmasdfghjklqwertyuiop1234567890") for i in range(length)) 

def aes_encrypt(aes_key, aes_iv, raw ):
    cipher = AES.new( hashlib.sha256(aes_key).digest(), AES.MODE_CBC, hashlib.md5(aes_iv).digest() )
    return cipher.encrypt(pad(raw))
 
def aes_decrypt(aes_key, aes_iv, raw ):
    cipher = AES.new( hashlib.sha256(aes_key).digest(), AES.MODE_CBC, hashlib.md5(aes_iv).digest() )
    return unpad(cipher.decrypt(raw))
   
def Send_Data(GWIP, method, data, GWPORT):
    try:
        aes_key = randomword(32)
        aes_iv = randomword(32)
        
        send_data = {'method':method, 'aes_key':aes_key, 'aes_iv':aes_iv}
        plan_send_data = json.dumps(send_data)
        
        keyPub = RSA.importKey(open('pub.pem', 'r').read())
        
           
        keyPub = PKCS1_OAEP.new(keyPub)
        enc_send_data = keyPub.encrypt(plan_send_data)    
        
        enc_data = aes_encrypt(aes_key, aes_iv, data)
        
        #print aes_key, aes_iv
       # print enc_data.encode('hex')
        #print pybase64.standard_b64encode(enc_data)
        last_data = json.dumps({'1':pybase64.standard_b64encode(enc_send_data), '2':pybase64.standard_b64encode(enc_data)})
        
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(15)
        s.connect((GWIP, int(GWPORT)))
        #print len(last_data)
        s.send(struct.pack('I', len(last_data))+last_data)
        
        enc_recv_data = ''
        data_len = struct.unpack('I', s.recv(4))[0]
        output = cStringIO.StringIO()
        tttmp_len = 0
        while True:
            tttmp = s.recv(data_len)
            output.write(tttmp)
            tttmp_len = tttmp_len+len(tttmp)
            if data_len <= tttmp_len:
                break
        enc_recv_data = output.getvalue()
        output.close()
        plan_recv_data = json.loads(aes_decrypt(aes_key, aes_iv, enc_recv_data))
        #print u"GW 로 부터 응답 받은 데이터"
        #print '->', plan_recv_data
        return (True, plan_recv_data)
    except Exception, e:
        return (False, str(e))
    
if __name__ == '__main__':
    pass
    '''
    import time
    x = time.strptime("2018-05-24 14:59:59", "%Y-%m-%d %H:%M:%S")


    print time.mktime(x)
    #x = time.strptime("2018-05-24 14:59:59", ' %H:%M:%S')
    #print datetime.timedelta(hours=x.tm_hour,minutes=x.tm_min,seconds=x.tm_sec).total_seconds()
    
    exit()
    
    print u'로그인 사용할 인증서를 선택 및 접속 가능 장비 목록 수신'
    CSN, Cert, Certindex, IDN = wizstick_cert_view('00000000')
    
    if False:
        print u'스틱 사용자 등록'
        reg_data = regapi(CSN, Cert, Certindex, IDN, '00000000')
        Send_Data('REG', reg_data, 5050)  
    
    if False:
        print u'인증접속'
        print u'GW 서버로 부터 접속 정보 얻기'
        forward_to_ip, forward_to_port, authkey = auth(CSN, Cert, Certindex, IDN, '00000000', '20170912182531842006')
        print u'PC 로컬 포워드 기능 활성화 및 인증접속'
        threading.Thread(target=th_server, args=(str('20170912182531842006'),forward_to_ip, forward_to_port, authkey)).start()
        '''