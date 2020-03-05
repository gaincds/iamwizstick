#-*- coding: utf-8 -*-
#import gevent.monkey
#gevent.monkey.patch_socket()
#import socket
#from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5 as PKCS1_v1_5_sign 
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Cipher import AES
import Crypto
import M2Crypto

import hmac
import os, time, json, struct, random
import pybase64
import hashlib
from asn1crypto.x509 import Certificate
from gevent.server import StreamServer
from gevent.pool import Pool
from gevent import Timeout


import pycurl
from StringIO import StringIO
import cjson
import re
import OpenSSL

import customDB
import forward_server2
import RDP_mitm
import multiprocessing
import socket



BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS) 
unpad = lambda s : s[:-ord(s[len(s)-1:])]

#keyPri = RSA.importKey(open('aaa.pem', 'r').read())
ReadRSA = M2Crypto.RSA.load_key ('aaa.pem')
CRL_list_dic = {}
mypool = customDB.pool.QueuePool(customDB.getconn, max_overflow=2, pool_size=2, recycle=10)


def device_auth(Device_key, Random_key):
    try:
        logger.info("\t Input Device_key 1 (%s/32) : %s"%(len(Device_key), [Device_key]))
        Device_key = Device_key.decode('hex')
        logger.info("\t Input Device_key 2 (%s/16) : %s"%(len(Device_key), [Device_key]))
    except Exception, e:
        logger.error("Input Device_key Error on line (%s) : %s " % (sys.exc_info()[-1].tb_lineno, str(e)))
        return False
    Random_key = Random_key.decode('hex')
    try:
        tmp = ''
        for i in range(0, 8):
            tmp += chr(ord(Device_key[i+8]) ^ ord(Random_key[i]))
        for i in range(8, 16):
            tmp += chr(ord(Device_key[i-8]) ^ ord(Random_key[i]))    
        return hashlib.md5(tmp).hexdigest()
    except Exception, e:
        logger.error("Device_auth Error on line (%s) : %s " % (sys.exc_info()[-1].tb_lineno, str(e)))
        return False

def pubkey_enc(Cert):
    cert = Certificate.load(Cert)
    n = cert.public_key.native["public_key"]["modulus"]
    e = cert.public_key.native["public_key"]["public_exponent"]
    rsakey = RSA.construct(( long(n), long(e)))
    authkey = os.urandom(128)
    enc_data = rsakey.encrypt(authkey, 'x')[0]
    return (enc_data, authkey)

def PK_GEN(IDN, Cert, CSN):
    cert = Certificate.load(Cert)
    n = cert.public_key.native["public_key"]["modulus"]
    m = hashlib.sha224()
    m.update(IDN)
    m.update(str(n))
    m.update(CSN)
    return m.hexdigest()

def signer_verify(Cert, Indata, Sign_data):
    cert = Certificate.load(Cert)
    n = cert.public_key.native["public_key"]["modulus"]
    e = cert.public_key.native["public_key"]["public_exponent"]
    rsakey = RSA.construct(( long(n), long(e)))
    if Indata== rsakey.encrypt(Sign_data,  'x')[0]:
        return True
    return False

def aes_encrypt(aes_key, aes_iv, raw ):
    #cipher = AES.new( hashlib.sha256(aes_key).digest(), AES.MODE_CBC, hashlib.md5(aes_iv).digest() )
    #return cipher.encrypt(pad(raw))
    aes = M2Crypto.EVP.Cipher(alg='aes_256_cbc', key=hashlib.sha256(aes_key).digest(), iv=hashlib.md5(aes_iv).digest(), op=1, padding=True)
    return aes.update(raw)+aes.final()

def aes_decrypt(aes_key, aes_iv, raw ):
    #cipher = AES.new( hashlib.sha256(aes_key).digest(), AES.MODE_CBC, hashlib.md5(aes_iv).digest() )
    #return unpad(cipher.decrypt(raw))
    aes = M2Crypto.EVP.Cipher(alg='aes_256_cbc', key=hashlib.sha256(aes_key).digest(), iv=hashlib.md5(aes_iv).digest(), op=0, padding=True)
    return aes.update(raw)+aes.final()

def X509Store_init(PATH):
    store = OpenSSL.crypto.X509Store()
    for filename in os.listdir(PATH):
        content = open(os.path.join(PATH, filename), 'rb').read()
        store.add_cert(OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, content))  
    return store

def X509Store_verify(Cert):
    store_ctx = OpenSSL.crypto.X509StoreContext(X509store, OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, Cert))
    try:
        store_ctx.verify_certificate()
        return True
    except OpenSSL.crypto.X509StoreContextError as e:
        return False
     
def CRL(Cert):
    #return (True,'')
    #https://pyopenssl.org/en/stable/api/crypto.html#x509-objects
    cert = Certificate.load(Cert)
    cert.ocsp_urls
    serial_number = cert['tbs_certificate']['serial_number'].native
    validity_after = cert['tbs_certificate']['validity'].native['not_after']
    
    
    x = time.strptime(str(validity_after).split('+')[0], "%Y-%m-%d %H:%M:%S")
    if time.time() > time.mktime(x):
        return (False, u'인증서 유효기간 만료')
    
    #validity_befor = cert['tbs_certificate']['validity'].native['not_befor']
    #subject =  cert['tbs_certificate']['subject'].native['common_name']
    #issuer = cert['tbs_certificate']['issuer'].native['common_name']
    #https://www.rootca.or.kr/kor/accredited/accredited03_01View.jsp?seqno=41
    #policy_identifier = OIDlist[cert._certificate_policies_value.native[0]['policy_identifier']][1]
    crl_distribution_points = cert._crl_distribution_points_value.native[0]['distribution_point'][0]
    #return True
    tmp_serial_number = "%08X" % (serial_number) 
    if len(CRL_list_dic) > 1000:
        CRL_list_dic.clear()
   
    if crl_distribution_points in CRL_list_dic.keys():
        date_tmp, CRL_tmp = CRL_list_dic[crl_distribution_points]
        if time.time() - date_tmp > 86400:
            pass
        else:
            tmp = pybase64.standard_b64decode(CRL_tmp)
            crl_object = OpenSSL.crypto.load_crl(OpenSSL.crypto.FILETYPE_ASN1, tmp)
            revoked_objects = crl_object.get_revoked()  
            for a in revoked_objects:         
                if tmp_serial_number == a.get_serial():
                    tmp = u'인증서 효력정지 (%s)'%a.get_reason()
                    return (False, tmp)      
            return (True,'')  
        
    buffer = StringIO()
    c = pycurl.Curl()
    c.setopt(c.URL, crl_distribution_points)
    c.setopt(c.WRITEDATA, buffer)
    c.perform()
    c.close()
    body = buffer.getvalue()

    for a in  body.split('\n'):
        if a.find('certificateRevocationList') > -1:
            CRL_list_dic[crl_distribution_points] = (time.time(), a.split()[1])
            tmp = pybase64.standard_b64decode(a.split()[1])
            crl_object = OpenSSL.crypto.load_crl(OpenSSL.crypto.FILETYPE_ASN1, tmp)
            revoked_objects = crl_object.get_revoked()
            for a in revoked_objects:
                if tmp_serial_number == a.get_serial():
                    return (False, a.get_reason())
                
    return (True,'')

def Time_verify(time_tmp):
    if abs(int(time.time()) - int(time_tmp)) > 20:
        return False
    return True

def randomword(length):
    return ''.join(random.choice("1234567890") for i in range(length)) 

def handle_data(recv_data, clientaddr):

    #enc_send_data = json.loads(keyPri.decrypt(pybase64.standard_b64decode(recv_data['1'])))
    try:
        enc_send_data =  cjson.decode(ReadRSA.private_decrypt (pybase64.standard_b64decode(recv_data['1']), M2Crypto.RSA.pkcs1_oaep_padding))
        #enc_send_data = json.loads(ReadRSA.private_decrypt (pybase64.standard_b64decode(recv_data['1']), M2Crypto.RSA.pkcs1_oaep_padding))
    except:
        return ''#cjson.encode({'method':'', 'result':'False', 'data':u'전송데이터 복호화 실패'})

    method = enc_send_data['method']
    aes_key = enc_send_data['aes_key']
    aes_iv = enc_send_data['aes_iv']
    reg_data = aes_decrypt(aes_key, aes_iv, pybase64.standard_b64decode(recv_data['2']))
    msg = json.loads(reg_data)
    
    if method == 'Tmp_Auth':
        if Time_verify(msg['Time']) == False:
            return aes_encrypt(aes_key, aes_iv, cjson.encode({'method':method, 'result':'False', 'data':u'전송데이터의 시간 값이 유효하지 않습니다.'}) ) 
        
        #print clientaddr # if clientaddr[0] == 127.0.0.1
        
        PK = msg['PK']
        Return_Msg = customDB.mysql_User_Authorization(mypool, (msg['EQP_UID'], PK)) 
        if Return_Msg[0] != True:
            return aes_encrypt(aes_key, aes_iv,  cjson.encode({'method':method, 'result':'False', 'data':Return_Msg[1]}) )

        authkey = randomword(6)
        
        if Return_Msg[1]['PROTOCOL'] == 'SSH':
            port = forward_server2.setup(authkey, msg['EQP_UID'], PK, Return_Msg[1], False, tmp_auth = True)
            
        elif Return_Msg[1]['PROTOCOL'] == 'RDP':
            Return_Msg[1]['EQP_UID'] = msg['EQP_UID']
            Return_Msg[1]['PK'] = PK
            #queue = ''#multiprocessing.Queue()
            port = RDP_mitm.setup(authkey, PK, Return_Msg[1], '', False, tmp_auth = True)
            #dbin =  multiprocessing.Process(target=RDP_mitm.q_insert, args=(queue, ) )
            #dbin.start()   
        
        #port = forward_server2.setup(authkey, msg['EQP_UID'], PK, Return_Msg[1], False, tmp_auth = True)
  
        
        return aes_encrypt(aes_key, aes_iv, json.dumps({'method':method, 'result':'True', 'authkey':authkey, 'port':port}) )
          
    Indata = hashlib.sha256(msg['msg']).digest()
    msg_hash =  pybase64.standard_b64decode(msg['msg_hash'])
    if msg_hash != Indata:
        return False
    #msg_b =  json.loads(msg['msg'])
    msg_b = cjson.decode(msg['msg'])
    
    if Time_verify(msg_b['Time']) == False:
        return aes_encrypt(aes_key, aes_iv, cjson.encode({'method':method, 'result':'False', 'data':u'전송데이터의 시간 값이 유효하지 않습니다.'}) ) 
    
    Cert =  pybase64.standard_b64decode(msg_b['Cert'])
    
    if X509Store_verify(Cert) == False:
        return aes_encrypt(aes_key, aes_iv, cjson.encode({'method':method, 'result':'False', 'data':u'사설인증서 또는 검증 되지 않은 인증서 사용' }) ) 
    
    CRL_result = CRL(Cert)
    if CRL_result[0] == False:
        return aes_encrypt(aes_key, aes_iv, cjson.encode({'method':method, 'result':'False', 'data':CRL_result[1]}) ) 
    
    msg_hash =  pybase64.standard_b64decode(msg['msg_hash'])
    Sign_data =  pybase64.standard_b64decode(msg['Sign_data'])    
    
    if signer_verify(Cert, msg_hash, Sign_data):
        if method == 'REG':
            if re.findall(r'\W', msg_b['User_ID']) or re.findall(r'[!^ \u3131-\u3163\uac00-\ud7a3]+', msg_b['Name']) or re.findall(r'[!^ \u3131-\u3163\uac00-\ud7a3]+\W', msg_b['ORG']) or re.findall(r'\D', msg_b['Phone_number']) or  len(msg_b['Phone_number']) > 13 or bool(re.search(r"^[\w\.\+\-]+\@[\w]+\.[a-z]{2,3}$", msg_b['Email'])) == False :
                return aes_encrypt(aes_key, aes_iv, cjson.encode({'method':method, 'result':'False', 'data':u'입력값이 유효하지 않습니다.'}))                      
            tmp = (PK_GEN(msg_b['IDN'], Cert, msg_b['CSN']), msg_b['Name'], msg_b['ORG'], msg_b['Phone_number'], msg_b['Email'] , time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()), msg_b['User_ID'],  msg_b['CSN'])
            Return_Msg = customDB.mysql_User_insert(mypool, tmp)    
            return aes_encrypt(aes_key, aes_iv, cjson.encode({'method':method, 'result':Return_Msg[0], 'data':Return_Msg[1]}))
                
        elif method == 'Auth':
            PK = PK_GEN(msg_b['IDN'], Cert, msg_b['CSN'])
            Return_Msg = customDB.mysql_User_Authorization(mypool, (msg_b['EQP_UID'], PK))
            if Return_Msg[0] != True:
                return aes_encrypt(aes_key, aes_iv,  cjson.encode({'method':method, 'result':'False', 'data':Return_Msg[1]}) )
                     
            enc_data, authkey = pubkey_enc(Cert)
            if Return_Msg[1]['PROTOCOL'] == 'SSH':
                port = forward_server2.setup(authkey, msg_b['EQP_UID'], PK, Return_Msg[1], False, tmp_auth = False)
            elif Return_Msg[1]['PROTOCOL'] == 'RDP':
                Return_Msg[1]['EQP_UID'] = msg_b['EQP_UID']
                Return_Msg[1]['PK'] = PK
                #queue = ''#multiprocessing.Queue()
                port = RDP_mitm.setup(authkey, PK, Return_Msg[1], '', False, tmp_auth = False)
                #dbin =  multiprocessing.Process(target=RDP_mitm.q_insert, args=(queue, ) )
                #dbin.start()
            else:
                return aes_encrypt(aes_key, aes_iv,  cjson.encode({'method':method, 'result':'False', 'data':'Unknow PROTOCOL'}) )
            return aes_encrypt(aes_key, aes_iv, cjson.encode({'method':method, 'result':'True', 'data':pybase64.standard_b64encode(enc_data), 'port':port}) )
        
        elif method == 'List':
            PK = PK_GEN(msg_b['IDN'], Cert, msg_b['CSN'])
            Return_Msg = customDB.mysql_EQP_List(mypool, (PK,))
            return aes_encrypt(aes_key, aes_iv, cjson.encode({'method':method, 'result':Return_Msg[0], 'data':Return_Msg[1]}))

    else:
        return aes_encrypt(aes_key, aes_iv, cjson.encode({'method':method, 'result':'False', 'data':u'서명검증에 실패하였습니다.'}) )



def echo(clientsock, clientaddr):
    try:
        with Timeout(10):
            rfileobj = clientsock.makefile(mode='rb')
            tmp = rfileobj.read(4)
            if len(tmp) == 0:
                rfileobj.close()
                return
            data_len = struct.unpack('I', tmp)[0]
            if data_len > 6000:
                pass
            else:
                recv_data = ''
                while True:
                    recv_data += rfileobj.read(data_len)
                    if len(recv_data) == data_len:
                        break
                send_data = handle_data(json.loads(recv_data), clientaddr)
                if send_data !=  False:
                    clientsock.sendall(struct.pack('I', len(send_data))+send_data)
                    
            rfileobj.close()
    except Exception, e:
        print e
        #customDB.mysql_except_log_insert((time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()), 2,str(e), socket.gethostbyname(socket.gethostname())))
    
if __name__ == '__main__':
    
    
    X509store = X509Store_init('root_cert')
    
    try:
        while True:
            pool = Pool(100)
            server = StreamServer(('0.0.0.0', 5050), echo, spawn=pool)
            server.serve_forever()
    except Exception, e:
        print e    
