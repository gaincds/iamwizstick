#-*- coding: euc-kr -*-

import os
import struct
from binascii import unhexlify
import testp
import time
import serial, struct, time, binascii, re, string, random
import serial.tools.list_ports
import hashlib

from Crypto.Cipher import AES

WinXP = "\\Program Files\\NPKI"
Win7_8 = "\\Users\\"+os.getenv('USERNAME')+"\\AppData\\LocalLow\\NPKI"

# PUB_KEY, big-endian
KT_WZS_ALG_PUB_RSA512 = 0x00100080
KT_WZS_ALG_PUB_RSA1024 = 0x00100100
KT_WZS_ALG_PUB_RSA2048 = 0x00100200 # 00021000
KT_WZS_ALG_PUB_RSA3072 = 0x00100300
KT_WZS_ALG_PUB_RSA4096 = 0x00100400
KT_WZS_ALG_PUB_ECC = 0x00200000

PUB_EM_dic = {
              'KT_WZS_PUB_EM_NONE' :   0x00,
              'KT_WZS_PUB_EM_V15'   : 0x15,
              'KT_WZS_PUB_EM_OAEP_SHA1':    0x21,
              'KT_WZS_PUB_EM_OAEP_SHA256' :   0x22,
              'KT_WZS_PUB_EM_PSS_SHA1'  :  0x23,
              'KT_WZS_PUB_EM_PSS_SHA256' :   0x24
              }

HASH_ALG_dic ={
    'KT_WZS_ALG_HASH_MD5'   : 0x01,
    'KT_WZS_ALG_HASH_SHA1'   : 0x02,
    'KT_WZS_ALG_HASH_SHAMD5'  :  0x03,
    'KT_WZS_ALG_HASH_HAS160'  :  0x04,
    'KT_WZS_ALG_HASH_HMAC'  :  0x05,
    'KT_WZS_ALG_HASH_SHA256' :   0x10,
    'KT_WZS_ALG_HASH_SHA384'  :  0x20,
    'KT_WZS_ALG_HASH_SHA512'  :  0x30
}

KT_WZS_KEY_USAGE_dic ={
            'KT_WZS_KEY_USAGE_SIGN'   : 0x01,
            'KT_WZS_KEY_USAGE_ENCRYPT' :   0x02
            }

PUB_KEY_dic = {
               'KT_WZS_ALG_PUB_RSA512'  :  0x00100080,
               'KT_WZS_ALG_PUB_RSA1024'  :  0x00100100,
               'KT_WZS_ALG_PUB_RSA2048'   : 0x00100200,
               'KT_WZS_ALG_PUB_RSA3072'   : 0x00100300,
               'KT_WZS_ALG_PUB_RSA4096'   : 0x00100400,
               'KT_WZS_ALG_PUB_ECC'   : 0x00200000
            }

OP_CODE = {
           'KT_WZS_OP_IDENTITY' : 0x01,
           'KT_WZS_OP_STATUS'    : 0x02,
            'KT_WZS_OP_FP_REGIST'    : 0x03,
            'KT_WZS_OP_FP_INIT'    : 0x04,
            'KT_WZS_OP_FP_VERIFY'    : 0x05,
            'KT_WZS_OP_FP_STATUS'    : 0x06,
            'KT_WZS_OP_HASH_CREAT'    : 0x07,
            'KT_WZS_OP_HASH_UPDATE'    : 0x08,
            'KT_WZS_OP_HASH_SET'    : 0x09,
            'KT_WZS_OP_HASH_DUP'    : 0x0A,
            'KT_WZS_OP_HASH_DEL'    : 0x0B,
            'KT_WZS_OP_KEYPAIR_GEN'    : 0x0C,
            'KT_WZS_OP_PUB_ENC'    : 0x0D,
            'KT_WZS_OP_PUB_DEC'    : 0x0E,
            'KT_WZS_OP_PUB_FIND'    : 0x0F,
            'KT_WZS_OP_PUB_DEL'    : 0x10,
            'KT_WZS_OP_PUB_IMPORT'    : 0x11,
            'KT_WZS_OP_SYM_GEN'    : 0x12,
            'KT_WZS_OP_SYM_IMPORT'    : 0x13,
            'KT_WZS_OP_SYM_DUP'    : 0x14,
            'KT_WZS_OP_SYM_DEL'    : 0x15,
            'KT_WZS_OP_SYM_EXPORT'   : 0x16,
            'KT_WZS_OP_PUB_SIGN'    : 0x17,
            'KT_WZS_OP_PUB_VERIFY'    :0x18,
            'KT_WZS_OP_SYM_ENC'    : 0x19,
            'KT_WZS_OP_SYM_DEC'    :0x1A,
            'KT_WZS_OP_ATTR_SET'    : 0x1B,
            'KT_WZS_OP_ATTR_GET'    : 0x1C,
            'KT_WZS_OP_RAND_SEED'    : 0x1D,
            'KT_WZS_OP_RAND_GEN'    : 0x1E
            }
ATTR_dic = {
    'KT_WZS_ATTR_IDENTITY'    : 0x00,
    'KT_WZS_ATTR_HW_VER'    : 0x01,
    'KT_WZS_ATTR_FW_VER'    : 0x02,
    'KT_WZS_ATTR_CONTAINER'    : 0x03,
    'KT_WZS_ATTR_SYM_KEY'    : 0x04,
    'KT_WZS_ATTR_IV'    : 0x05,
    'KT_WZS_ATTR_SYM_ALG'    : 0x06,
    'KT_WZS_ATTR_SYM_MODE'    : 0x07,
    'KT_WZS_ATTR_SYM_PADDING'    : 0x08,
    'KT_WZS_ATTR_SYM_EXPORT'    : 0x09,
    'KT_WZS_ATTR_HASH_VAL'    : 0x0A,
    'KT_WZS_ATTR_HASH_ALG'    : 0x0B,
    'KT_WZS_ATTR_CERT_KID'    : 0x0C,
    'KT_WZS_ATTR_PUB_KEY'    : 0x0D,
    'KT_WZS_ATTR_PRI_KEY'    : 0x0E,
    'KT_WZS_ATTR_PRI_KEY_CONT'    : 0x0F,
    'KT_WZS_ATTR_KVID_R'    : 0x10,
    'KT_WZS_ATTR_CERT_SUB'    : 0x11,
    'KT_WZS_ATTR_CERT_ISSUER'    : 0x12,
    'KT_WZS_ATTR_CERT_SERIAL'    : 0x13,
    'KT_WZS_ATTR_CERT'    : 0x14,
    'KT_WZS_ATTR_CERT_CONT'    : 0x15,
    'KT_WZS_ATTR_LABEL'    : 0x16,
    'KT_WZS_ATTR_EXPOTABLE'    : 0x17,
    'KT_WZS_ATTR_CERT_LIST'    : 0x18,
    'KT_WZS_ATTR_CONTAINER_CONT'    : 0x19,
    'KT_WZS_ATTR_USAGE' : 0x1a ,
    'KT_WZS_ATTR_CORP_NUM'  :  0x1B,
    'KT_WZS_ATTR_JUMIN_NO1'  :  0x1C,
    'KT_WZS_ATTR_JUMIN_NO2'  :  0x1D,
    'KT_WZS_ATTR_JUMIN_NO3'  :  0x1F
    }

KT_WZS_KEY_USAGE_dic ={
    'KT_WZS_KEY_USAGE_SIGN'   : 0x01,
    'KT_WZS_KEY_USAGE_ENCRYPT' :   0x02
}
#print Win7_8




KEY = '0000000000000000000000000000000000000000000000000000000000000000'.decode('hex')
IV = '00000000000000000000000000000000'.decode('hex')
KEYadmin = '0000000000000000000000000000000000000000000000000000000000000000'.decode('hex')
serial_name = ''
serial_name_user = ''
serial_name_admin = ''

pc_tmp_dic ={}
baud_rate = 115200
BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS) 
unpad = lambda s : s[0:-ord(s[-1])]



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
    a = '\xff\xff\xff\xff\xff'
    b = '\x00'*112
    c = '\x01'*16
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

def add_padding_a(padding, data):
    result_data = data+binascii.unhexlify(id_generator(padding).encode('hex'))+struct.pack('B',padding)
    return result_data

def sum_padding(data, id):
    tt = struct.pack('q',time.time())
    pc_tmp_dic[id] = tt+tt
    data = data+tt
    a,b = divmod(len(data),16)
    padding = 15-b
    if padding == 0:
        padding = 16
        return add_padding_a(padding, data)
    else:
        return add_padding_a(padding, data)
        
def id_generator(size=6, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))

def Recv_data_paser(data):
    try:
        DATA = {}
        if len(data) > 0:
            seek = 0
            while True:
                Data_Tag = struct.unpack('<L', data[seek:seek + 4])[0]
                Len = struct.unpack('<L', data[seek + 4:seek + 8])[0]
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
    except Exception, e:
        print e 
        return False
        
def send_data(cmd, data, serial_name, KEY, Sign_value_tmp = '\x01', flag_ = False, id_tmp = 64):
    try:
        PID = struct.pack('L', 136)+ struct.pack('L', 4)+struct.pack('L', 1)
        TID = struct.pack('L', 137)+ struct.pack('L', 4)+struct.pack('L', 1)
        DDD = struct.pack('L', 135)+ struct.pack('L', 4)+struct.pack('L', 1)
        if Sign_value_tmp != '\x01':
            Sign_value = struct.pack('L', 134)+ struct.pack('L', len(Sign_value_tmp))+Sign_value_tmp
            data = data+PID+TID+Sign_value+DDD
        else:
            data = data+PID+TID+DDD
                       
        PLAINTEXT = struct.pack('B', cmd)+struct.pack('H', len(data))+data
        obj = AES.new(KEY, AES.MODE_CBC, IV)
        id_tmp = struct.pack('B', 64)
        CIPHERTEXT = obj.encrypt(sum_padding(PLAINTEXT, id_tmp))
        data_len = struct.pack('>I', len(CIPHERTEXT))
        send_data = id_tmp+data_len+CIPHERTEXT
        
        conn = serial.Serial(serial_name, baud_rate, timeout=5)
        conn.write(send_data)

        if flag_ == True:
            while True:
                data_a = ''
                while 5 > len(data_a):
                    data = conn.read(1)
                    data_a += data 
                Total_Len = struct.unpack('>I', data_a[1:5])[0]
                event = ''
                c_L = Total_Len
                while Total_Len > len(event):
                    data = conn.read(c_L)
                    event += data
                    c_L = c_L - len(data)        
                obj = AES.new(KEY, AES.MODE_CBC, pc_tmp_dic[id_tmp])
                recv_data = unpad(obj.decrypt(event))
                if recv_data[0:3] == '\xff\xff\xff':
                    print recv_data[3:]
                else:
                    conn.close()
                    if id_tmp != 64:
                        return recv_data
                    return Recv_data_paser(recv_data[3:])

        data_a = ''
        while 5 > len(data_a):
            data = conn.read(1)
            data_a += data 
        Total_Len = struct.unpack('>I', data_a[1:5])[0]
        event = ''
        c_L = Total_Len
        while Total_Len > len(event):
            data = conn.read(c_L)
            event += data
            c_L = c_L - len(data)
        obj = AES.new(KEY, AES.MODE_CBC, pc_tmp_dic[id_tmp])
        recv_data = unpad(obj.decrypt(event))
        recv_data[0]
        recv_data[1:3]
        conn.close()
        return Recv_data_paser(recv_data[3:])
    except Exception, e:
        print e
        set()
        return False

def Data_pack(data):
    result = ''
    keylist = data.values()
    keylist.sort()
    for a in keylist: 
        TAG = struct.pack('<L', a[0])
        if a[2] == 'N':
            VALUE = struct.pack('<L', a[1])
        elif a[2] == 'S':
            VALUE = a[1]  # binascii.unhexlify(a[1].encode('hex'))
        elif a[2] == 'B':
            VALUE = a[1]
        else:
            pass
        LEN = struct.pack('<L', len(VALUE))
        result = result + TAG + LEN + VALUE
    return result       

def get_cert_list():
    cert_list = {}
    number = 1
    for (path, dir, files) in os.walk("c:\\"+Win7_8):
        for filename in files:
            ext = os.path.splitext(filename)
            #print ext[-1]
            if path.find('\\USER\\') > -1 or path.find('\\User\\') > -1:
                if ext[-1] == '.der':# or ext[-1] == '.key'
                    #print("%s\%s" % (path, filename))
                    p = testp.PinkSign()
                    tmp = "%s\%s" % (path, filename)
                    p.load_pubkey(pubkey_path=tmp)
                    #print p.serialnum(), p.valid_date()
                    #print p.issuer(), p.dn()
                    #print p.serialnum()
                    #p.extraction_prikey(path, 'dnfleotjd1!')
                    if ext[-2].find('signCert') > -1:
                        #cert_list.append(tmp)
                        cert_list[number] = [path, filename]
                        number = number + 1
                    #if p.serialnum() == 481667431:
                        #print p.extraction_prikey(path+"\SignPri.key", 'dnfleotjd1!').encode('hex')
                        #pass
    return cert_list


def cert_paser(recv_data):
    try:
        index_count = 0
        index_tmp = []
        for c in recv_data:
            if c == '$':
               index_tmp.append(index_count)
            index_count = index_count + 1
        UUID = recv_data[0:index_tmp[0]]
        SKI = recv_data[index_tmp[0]+1:index_tmp[1]]
        cert = recv_data[index_tmp[1]+1:]
        return UUID, SKI, cert
    except Exception, e:
        print e
                

if __name__ == '__main__':
    set()
    
    #recv_udp()
    
    
    
    import testp
 

    print testp.get_cert_list()
    
    exit()
    print 'C_Initialize'
    print send_data(160, '', serial_name_user, KEY)
    
    print 'C_GetBioFingerAuthState'
    data = Data_pack({'hSession':[0x00000001, 0, 'N'], 'flags':[0x00000002, 2, 'N']})
    print send_data(224, data, serial_name_user, KEY)
    
    print 'C_OpenSession'
    data = Data_pack({'slotID':[0x00000001, 0, 'N'], 'flags':[0x00000002, 6, 'N']})
    tmp = send_data(169, data, serial_name_user, KEY)
    print tmp
    hSession = struct.unpack('<L', tmp[2])[0]
    print hSession
    
    print 'C_Login'
    data = Data_pack({'hSession':[0x00000001, hSession, 'N'], 'CK_USER_TYPE':[0x00000002, 1, 'N'], 'PIN':[0x00000003, '00000000', 'B']})
    print send_data(173, data, serial_name_user, KEY)    
    
    
    path = ['c:\\\\Users\\ktdev01\\AppData\\LocalLow\\NPKI\\yessign\\User\\cn=\xc1\xb6\xb4\xeb\xbc\xba(cho dae sung)0020049200606157221843,ou=WOORI,ou=personal4IB,o=yessign,c=kr\\']
    Certificate, PublicKey, PrivateKey, Data =  testp.pki_paser(hSession, path[0], 'dnfleotjd1!')
    
    

    
    #Certificate['CKA_ID']
    #Data['CKA_LABLE']
    
    print 'C_FindObjectsInit'
    data = Data_pack({'hSession':[0x00000001, hSession, 'N'], 'CKA_ID':Certificate['CKA_ID'], })
    print send_data(184, data, serial_name_user, KEY)  
    print 'C_FindObjects'
    data = Data_pack({'hSession':[0x00000001, hSession, 'N']})
    result = send_data(185, data, serial_name_user, KEY)             
    print 'C_FindObjectsFinal'
    data = Data_pack({'hSession':[0x00000001, hSession, 'N']})
    print send_data(186, data, serial_name_user, KEY)  
    if 2 in result.keys():
        b = 0
        for a in range(len(result[2])/4):
            b =  b+4
            print 'C_DestroyObject'
            data = Data_pack({'hSession':[0x00000001, hSession, 'N'], 'handle':[0x00000002, result[2][a*4:b], 'B'], })
            print send_data(183, data, serial_name_user, KEY)     
    
    print 'C_FindObjectsInit'
    data = Data_pack({'hSession':[0x00000001, hSession, 'N'], 'CKA_LABLE':Data['CKA_LABLE'], })
    print send_data(184, data, serial_name_user, KEY)  
    print 'C_FindObjects'
    data = Data_pack({'hSession':[0x00000001, hSession, 'N']})
    result = send_data(185, data, serial_name_user, KEY)          
    print 'C_FindObjectsFinal'
    data = Data_pack({'hSession':[0x00000001, hSession, 'N']})
    print send_data(186, data, serial_name_user, KEY)      
    if 2 in result.keys():
        b = 0
        for a in range(len(result[2])/4):
            b =  b+4
            print 'C_DestroyObject'
            data = Data_pack({'hSession':[0x00000001, hSession, 'N'], 'handle':[0x00000002, result[2][a*4:b], 'B'], })
            print send_data(183, data, serial_name_user, KEY)         
    
    

    print 'C_CreateObject_PRIVATE_KEY'
    data = Data_pack(PrivateKey)
    print send_data(179, data, serial_name_user, KEY)  
    
    print 'C_CreateObject_DATA'
    data = Data_pack(Data)
    print send_data(176, data, serial_name_user, KEY)      
    
    print 'C_CreateObject_PUBLIC_KEY'
    data = Data_pack(PublicKey)
    print send_data(178, data, serial_name_user, KEY)   
    
    print 'C_CreateObject_CERTIFICATE'
    data = Data_pack(Certificate)
    print send_data(177, data, serial_name_user, KEY)   

       
    #print 'C_BioFingerAuth'
    #data = Data_pack({'hSession':[0x00000001, hSession, 'N']})
    #print send_data(225, data, serial_name_user, KEY)        
    
    print 'C_Logout'
    data = Data_pack({'hSession':[0x00000001, hSession, 'N']})
    print send_data(174, data, serial_name_user, KEY)    

    print 'C_CloseSession'
    data = Data_pack({'hSession':[0x00000001, hSession, 'N']})
    print send_data(170, data, serial_name_user, KEY)    
    
    print 'C_Finalize'
    print send_data(161, '', serial_name_user, KEY)
    
    #data = Data_pack({'hSession_value':[0x00000001, ChID, 'N'], 'PIN':[0x00000002, str(pin_number), 'B']})
    
    exit()
    
    if False:
        
        data_tmp = binascii.unhexlify('LEDTEST'.encode('hex'))
        data = sum_padding(data_tmp)
        
        data_ccc = struct.pack('B',186)+struct.pack('>h',len(data))+data
        data_bbb = encrypt_aes256(data_ccc)
        hid_send(data_bbb, 1)
        
        exit()
        
        print finger_STATUS().encode('hex')
        
        #hHash = hash_init('KT_WZS_ALG_HASH_SHA256')
        #print hash_set(hHash, '00010203').encode('hex')
        #print hash_update(hHash, '00010203').encode('hex')
        
        #exit()
        
        hHnd = cert_paser(ATTR_GET('01000000', 'KT_WZS_ATTR_CERT_LIST'))[1][0:4]
        print ATTR_GET(hHnd.encode('hex'), 'KT_WZS_ATTR_PUB_KEY').encode('hex')
        
    
        OTP_CODE = finger_VERIFY()
        hHash = hash_init('KT_WZS_ALG_HASH_SHA256')
        
        print hash_set(hHash, hashlib.sha256("abc").hexdigest()).encode('hex')
        #OTP_CODE = OTP_CODE+1#binascii.unhexlify('00')
        print "*******************"
        print hashlib.sha256("abc").hexdigest()
        
        Sign_data =  SIGN(PUB_EM_dic['KT_WZS_PUB_EM_V15'], hHash, hHnd, OTP_CODE)
        print len(Sign_data), Sign_data.encode('hex')
        print "*******************"
        print PUB_VERIFY(PUB_EM_dic['KT_WZS_PUB_EM_V15'], hHash, hHnd, Sign_data).encode('hex')
        
    exit()
    
    
    #hPub = KEYPAIR_GEN()
    #print hPub.encode('hex')
    #print ATTR_GET(hPub.encode('hex'), 'KT_WZS_ATTR_PUB_KEY').encode('hex')
    
    result = get_cert_list()
    for a in result.keys():
        print a, result[a][0]+ '\\' +result[a][1]
    
    num = raw_input('>>')
    
    #print cert_list[int(num)]
    a = testp.PinkSign()
    a.load_pubkey(pubkey_path=result[int(num)][0]+"\\"+result[int(num)][1])
    pkey, r = a.extraction_prikey(result[int(num)][0]+"\SignPri.key", 'dnfleotjd1!')
    print pkey
    with open('cds.pey', 'w') as f:
        f.write(pkey)
    print r
    exit()
    #print pkey.encode('hex')
    data_tmp = struct.pack('i',KT_WZS_ALG_PUB_RSA2048)+struct.pack('B',KT_WZS_KEY_USAGE_dic['KT_WZS_KEY_USAGE_SIGN'])+binascii.unhexlify(pkey.encode('hex'))
    data = struct.pack('B',OP_CODE['KT_WZS_OP_PUB_IMPORT'])+struct.pack('<h',len(data_tmp))+data_tmp#+struct.pack('B',KT_WZS_KEY_USAGE_dic['KT_WZS_KEY_USAGE_SIGN'])+binascii.unhexlify(pkey.encode('hex'))#+binascii.unhexlify('88130000')
    
    #print data.encode('hex')
    print hid_send(data,2)

