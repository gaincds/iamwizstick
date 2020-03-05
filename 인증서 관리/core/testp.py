# coding=utf-8
import hashlib
import os
import random
from os.path import expanduser
from sys import platform as _platform

import re

from PBKDF import PBKDF1

from pyasn1.codec.der import decoder as der_decoder
from pyasn1.codec.der import encoder as der_encoder
from pyasn1.type.univ import Sequence, ObjectIdentifier, Null, Set, Integer, OctetString
from pyasn1.type import tag

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


import x509_parser
from Crypto.Util.number import long_to_bytes


id_seed_cbc = (1, 2, 410, 200004, 1, 4)
id_seed_cbc_with_sha1 = (1, 2, 410, 200004, 1, 15)
id_pkcs7_enveloped_data = (1, 2, 840, 113549, 1, 7, 3)

OIDlist = {
           # 1 법인, 2 개인, 3 용도제한
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
           '1.2.410.200004.5.2.1.7.3':[u'한국정보인증',u'개인신용카드',2,2],
           

            '1.2.410.200004.5.2.1.7.1':[u'한국정보인증',u'은행거래용/보험용'],
            '1.2.410.200004.5.2.1.7.2':[u'한국정보인증',u'증권거래용/보험용'],
            '1.2.410.200004.5.2.1.7.3':[u'한국정보인증',u'신용카드용'],
            '1.2.410.200004.5.1.1.9':[u'한국증권전산',u'용도제한용'],
            '1.2.410.200005.1.1.4':[u'금융결제원',u'은행/보험용'],
            '1.2.410.200005.1.1.6.2':[u'금융결제원',u'신용카드용'],
            '1.2.410.200004.5.4.1.101':[u'한국전자인증',u'인터넷뱅킹용'],
            '1.2.410.200004.5.4.1.102':[u'한국전자인증',u'증권거래용'],
            '1.2.410.200004.5.4.1.103':[u'한국전자인증',u'인터넷보험용'],
            '1.2.410.200004.5.4.1.104':[u'한국전자인증',u'신용카드용'],
            '1.2.410.200004.5.4.1.105':[u'한국전자인증',u'전자민원용'],
            '1.2.410.200004.5.4.1.106':[u'한국전자인증',u'인터넷뱅킹용/전자민원용'],
            '1.2.410.200004.5.4.1.107':[u'한국전자인증',u'증권거래용/전자민원용'],
            '1.2.410.200004.5.4.1.108':[u'한국전자인증',u'인터넷보험용/전자민원용'],
            '1.2.410.200004.5.4.1.109':[u'한국전자인증',u'신용카드용/전자민원용'],
            '1.2.410.200012.11.31':[u'한국무역정보통신',u'은행거래용(서명용)'],
            '1.2.410.200012.11.32':[u'한국무역정보통신',u'은행거래용(암호용)'],
            '1.2.410.200012.11.35':[u'한국무역정보통신',u'증권거래용(서명용)'],
            '1.2.410.200012.11.36':[u'한국무역정보통신',u'증권거래용(암호용)'],
            '1.2.410.200012.11.39':[u'한국무역정보통신',u'보험거래용(서명용)'],
            '1.2.410.200012.11.40':[u'한국무역정보통신',u'보험거래용(암호용)'],
            '1.2.410.200012.11.43':[u'한국무역정보통신',u'신용카드용(서명용)'],
            '1.2.410.200012.11.44':[u'한국무역정보통신',u'신용카드용(암호용)'],

           }


# utils
def get_npki_path():
    '''Return path for npki, depends on platform.
    This function can't manage certificates in poratble storage.
    Path for certifiacte is defined at http://www.rootca.or.kr/kcac/down/TechSpec/6.1-KCAC.TS.UI.pdf
    '''
    #print _platform
    WinXP = "\\Program Files\\NPKI"
    Win7_8 = "\\Users\\"+os.getenv('USERNAME')+"\\AppData\\LocalLow\\NPKI"
    
    if _platform == "linux" or _platform == "linux2":
        # linux
        path = expanduser("~/NPKI/")
    elif _platform == "darwin":
        # OS X
        suspect = ["~/Documents/NPKI/", "~/NPKI/", "~/Library/Preferences/NPKI/"]
        for p in suspect:
            path = expanduser("~/Documents/NPKI/")
            if os.path.isdir(path):
                return path
        raise "can't find certificate forder"

    elif _platform == "win32":
        result = []
        for path in [os.environ["ProgramFiles"]+"\\NPKI\\", os.environ["ProgramFiles(x86)"]+"\\NPKI\\", expanduser("~\\AppData\\LocalLow\\NPKI\\")]:
            if os.path.isdir(path):
                result.append(path)
        return result
    else:
        # default, but not expected to use this code.
        path = expanduser("~/NPKI/")
    return path

def seed_cbc_128_encrypt(key, plaintext, iv='0123456789012345'):
    '''general function - encrypt plaintext with seed-cbc-128(key, iv)'''
    backend = default_backend()
    cipher = Cipher(algorithms.SEED(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_text = padder.update(plaintext) + padder.finalize()
    encrypted_text = encryptor.update(padded_text)
    return encrypted_text


def seed_cbc_128_decrypt(key, ciphertext, iv='0123456789012345'):
    '''general function - decrypt ciphertext with seed-cbc-128(key, iv)'''
    backend = default_backend()
    cipher = Cipher(algorithms.SEED(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    decrypted_text = decryptor.update(ciphertext)
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_text = unpadder.update(decrypted_text) + unpadder.finalize()
    return unpadded_text


def seed_generator(size):
    '''general function - get random size-bytes string for seed'''
    return ''.join(chr(random.choice(range(255)) + 1) for _ in range(size))


def get_cert_list(basepath = None):
    cert_list = {}
    
    if basepath is not None:
        path_list = [basepath]
    else:
        path_list = get_npki_path()
        
    number = 1
    for a in path_list:
        for (path, dir, files) in os.walk(a):
            for filename in files:
                ext = os.path.splitext(filename)
                #print ext[-1]
                if path.find('\\USER\\') > -1 or path.find('\\User\\') > -1:
                    if ext[-1] == '.der':# or ext[-1] == '.key'
                        tmp = "%s\%s" % (path, filename)
                        cert_tmp = x509_parser.x509_print(open(tmp, 'rb').read())
                        
                        Subject = ''
                        for aa in cert_tmp['Subject'].split(','):
                            if aa.find('CN=') > -1:
                                Subject = aa.split('=')[1]
                        Issuer = ''
                        for aa in cert_tmp['Issuer'].split(','):
                            if aa.find('CN=') > -1:
                                Issuer = aa.split('=')[1]                        
                        
                        if cert_tmp['policy OID'] in OIDlist.keys():
                            oid = OIDlist[cert_tmp['policy OID']][1]
                        else:
                            oid = u'일반인증서'
                        if ext[-2].find('signCert') > -1:
                            #cert_list.append(tmp)
                            cert_list[number] = [path, filename, [oid, Subject, cert_tmp['After'], Issuer]]
                            number = number + 1
    return cert_list


def prikey_paser(hSession, path, passwd, key_id, Subject):
    d = open(path+'SignPri.key', 'rb').read()
    der = der_decoder.decode(d)[0]
    algorithm_type = der[0][0].asTuple()
    if algorithm_type not in (id_seed_cbc_with_sha1, id_seed_cbc):
        raise ValueError("prikey is not correct K-PKI private key file")
    salt = der[0][1][0].asOctets()  # salt for pbkdf#5
    iter_cnt = int(der[0][1][1])  # usually 2048
    cipher_key = der[1].asOctets()  # encryped private key
    dk = PBKDF1(passwd, salt, iter_cnt, 20)
    k = dk[:16]
    div = hashlib.sha1(dk[16:20]).digest()
    # IV for SEED-CBC has dependency on Algorithm type (Old-style K-PKI or Renewal)
    if algorithm_type == id_seed_cbc_with_sha1:
        iv = div[:16]
    else:
        iv = "123456789012345"
    prikey_data = seed_cbc_128_decrypt(k, cipher_key, iv)
    der_pri = der_decoder.decode(prikey_data)
    r = re.findall('\d+', (str(der_pri[0][3][1]).split('.')[1]).split(',')[0])
    r = int(r[0], 2)
    der_pri2 = der_decoder.decode(der_pri[0][2])
    
    PrivateKey = {'hSession':[0x00000001, hSession, 'N'], 
                   'CKA_CLASS':[0x00000002, 3, 'N'],
                   'CKA_ID':[0x00000003, key_id, 'B'],
                   'CKA_SUBJECT':[0x00000004, Subject, 'B'],
                   'CKA_LABLE':[0x00000005, 'KT Issued', 'B'],
                   'CKA_APPLICATION':[0x00000006, 'KT PKI APPLICATION', 'B'],
                   
                   'CKA_TOKEN':[0x00000007, 1, 'N'],
                   'CKA_PRIVATE':[0x00000008, 1, 'N'],
                    'CKA_MODIFIABLE' :[0x00000009, 0, 'N'],
                    'CKA_SIGN' :[0x00000010, 1, 'N'],
                    'CKA_VERIFY' :[0x00000011, 0, 'N'],
                    'CKA_ENCRYPT' :[0x00000012, 0, 'N'],
                    'CKA_DECRYPT' :[0x00000013, 0, 'N'],
                    'CKA_WRAP' :[0x00000014, 0, 'N'],
                    'CKA_UNWRAP' :[0x00000015, 0, 'N'],
                    'CKA_SENSITIVE' :[0x00000016, 1, 'N'],
                    'CKA_EXTRACTABLE' :[0x00000017, 0, 'N'],
                    'CKA_NEVER_EXTRACTABLE' :[0x00000018, 0, 'N'],
                    'CKA_KEY_TYPE' :[0x00000019, 0, 'N'],
                    'CKA_CERTIFICATE_TYPE' :[0x00000020, 0, 'N'],
                    'CKA_MODULUS_BITS' :[0x00000021, 0, 'N'],
                    
                    'CKA_MODULUS' : [0x00000022,long_to_bytes(long(der_pri2[0][1])), 'B'],
                    'CKA_PUBLIC_EXPONENT' : [0x00000023,long_to_bytes(long(der_pri2[0][2])),'B'],
                    'CKA_PRIVATE_EXPONENT' : [0x00000024,long_to_bytes(long(der_pri2[0][3])),'B'],
                    'CKA_PRIME_1' : [0x00000025,long_to_bytes(long(der_pri2[0][4])),'B'],
                    'CKA_PRIME_2' : [0x00000026,long_to_bytes(long(der_pri2[0][5])),'B'],
                    'CKA_EXPONENT_1' : [0x00000027,long_to_bytes(long(der_pri2[0][6])),'B'],
                    'CKA_EXPONENT_2' : [0x00000028,long_to_bytes(long(der_pri2[0][7])),'B'],
                    'CKA_COEFFICIENT' : [0x00000029,long_to_bytes(long(der_pri2[0][8])),'B'],

                    'CKA_TRUSTED' :[0x00000030, 0, 'N'],
                    'CKA_ALWAYS_SENSITIVE' :[0x00000031, 0, 'N'],
                    'CKA_WRAP_WITH_TRUSTED' :[0x00000032, 0, 'N'],
                    'CKA_ALWAYS_AUTHENTICATE' :[0x00000033, 0, 'N'],
                    'CKA_VALUE' :[0x00000099, prikey_data, 'B'],
                   }
   
    #rsa_keys = (long(der_pri2[0][1]), long(der_pri2[0][2]), long(der_pri2[0][3]), long(der_pri2[0][4]), long(der_pri2[0][5]))
    #prikey = RSA.construct(rsa_keys)
    #tmp = prikey.exportKey(format='DER', passphrase=None, pkcs=1)
    return PrivateKey, r

def pki_paser(hSession, path, passwd):
    file = open(path+'signCert.der', 'rb').read()
    cert  = x509_parser.x509_print(file)


    
    #cert['key id']
    #cert['Subject']
    #cert['Modulus']
    #cert['Exponent']
    #cert['keyUsage']
    
    Certificate = {'hSession':[0x00000001, hSession, 'N'], 
                   'CKA_CLASS':[0x00000002, 1, 'N'],
                   'CKA_ID':[0x00000003, cert['key id'], 'B'],
                   'CKA_SUBJECT':[0x00000004, cert['Subject'], 'B'],
                   'CKA_LABLE':[0x00000005, 'KT Issued', 'B'],
                   'CKA_APPLICATION':[0x00000006, 'KT PKI APPLICATION', 'B'],
                   'CKA_TOKEN':[0x00000007, 1, 'N'],
                   'CKA_PRIVATE':[0x00000008, 0, 'N'],
                    'CKA_MODIFIABLE' :[0x00000009, 0, 'N'],
                    'CKA_SIGN' :[0x00000010, 0, 'N'],
                    'CKA_VERIFY' :[0x00000011, 0, 'N'],
                    'CKA_ENCRYPT' :[0x00000012, 0, 'N'],
                    'CKA_DECRYPT' :[0x00000013, 0, 'N'],
                    'CKA_WRAP' :[0x00000014, 0, 'N'],
                    'CKA_UNWRAP' :[0x00000015, 0, 'N'],
                    'CKA_SENSITIVE' :[0x00000016, 0, 'N'],
                    'CKA_EXTRACTABLE' :[0x00000017, 0, 'N'],
                    'CKA_NEVER_EXTRACTABLE' :[0x00000018, 0, 'N'],
                    'CKA_KEY_TYPE' :[0x00000019, 0, 'N'],
                    'CKA_CERTIFICATE_TYPE' :[0x00000020, 0, 'N'],
                    'CKA_MODULUS_BITS' :[0x00000021, 0, 'N'],
                    'CKA_TRUSTED' :[0x00000030, 0, 'N'],
                    'CKA_ALWAYS_SENSITIVE' :[0x00000031, 0, 'N'],
                    'CKA_WRAP_WITH_TRUSTED' :[0x00000032, 0, 'N'],
                    'CKA_ALWAYS_AUTHENTICATE' :[0x00000033, 0, 'N'],
                    'CKA_VALUE' :[0x00000099, file, 'B'],
                   }
    
    PublicKey = {'hSession':[0x00000001, hSession, 'N'], 
                   'CKA_CLASS':[0x00000002, 2, 'N'],
                   'CKA_ID':[0x00000003, cert['key id'], 'B'],
                   'CKA_SUBJECT':[0x00000004, cert['Subject'], 'B'],
                   'CKA_LABLE':[0x00000005, 'KT Issued', 'B'],
                   'CKA_APPLICATION':[0x00000006, 'KT PKI APPLICATION', 'B'],
                   'CKA_TOKEN':[0x00000007, 1, 'N'],
                   'CKA_PRIVATE':[0x00000008, 0, 'N'],
                    'CKA_MODIFIABLE' :[0x00000009, 0, 'N'],
                    'CKA_SIGN' :[0x00000010, 0, 'N'],
                    'CKA_VERIFY' :[0x00000011, 0, 'N'],
                    'CKA_ENCRYPT' :[0x00000012, 0, 'N'],
                    'CKA_DECRYPT' :[0x00000013, 0, 'N'],
                    'CKA_WRAP' :[0x00000014, 0, 'N'],
                    'CKA_UNWRAP' :[0x00000015, 0, 'N'],
                    'CKA_SENSITIVE' :[0x00000016, 0, 'N'],
                    'CKA_EXTRACTABLE' :[0x00000017, 0, 'N'],
                    'CKA_NEVER_EXTRACTABLE' :[0x00000018, 0, 'N'],
                    'CKA_KEY_TYPE' :[0x00000019, 0, 'N'],
                    'CKA_CERTIFICATE_TYPE' :[0x00000020, 0, 'N'],
                    'CKA_MODULUS_BITS' :[0x00000021, 0, 'N'],
                    'CKA_MODULUS' :[0x00000022, cert['Modulus'], 'B'],
                    'CKA_PUBLIC_EXPONENT' :[0x00000023, long_to_bytes(cert['Exponent']), 'B'],
                    'CKA_TRUSTED' :[0x00000030, 0, 'N'],
                    'CKA_ALWAYS_SENSITIVE' :[0x00000031, 0, 'N'],
                    'CKA_WRAP_WITH_TRUSTED' :[0x00000032, 0, 'N'],
                    'CKA_ALWAYS_AUTHENTICATE' :[0x00000033, 0, 'N'],
                    'CKA_VALUE' :[0x00000099, file, 'B'],
                   }
        
    PrivateKey, r = prikey_paser(hSession, path, passwd, cert['key id'], cert['Subject'])

    R4VID = 'R4VID=%s'%cert['key id'].encode('hex')

    Data = {'hSession':[0x00000001, hSession, 'N'], 
                   'CKA_CLASS':[0x00000002, 0, 'N'],
                   'CKA_ID':[0x00000003, '', 'B'],
                   'CKA_SUBJECT':[0x00000004, '', 'B'],
                   'CKA_LABLE':[0x00000005, R4VID, 'B'],
                   'CKA_APPLICATION':[0x00000006, 'KT PKI APPLICATION', 'B'],
                   'CKA_TOKEN':[0x00000007, 1, 'N'],
                   'CKA_PRIVATE':[0x00000008,1, 'N'],
                    'CKA_MODIFIABLE' :[0x00000009, 0, 'N'],
                    'CKA_SIGN' :[0x00000010, 0, 'N'],
                    'CKA_VERIFY' :[0x00000011, 0, 'N'],
                    'CKA_ENCRYPT' :[0x00000012, 0, 'N'],
                    'CKA_DECRYPT' :[0x00000013, 0, 'N'],
                    'CKA_WRAP' :[0x00000014, 0, 'N'],
                    'CKA_UNWRAP' :[0x00000015, 0, 'N'],
                    'CKA_SENSITIVE' :[0x00000016, 0, 'N'],
                    'CKA_EXTRACTABLE' :[0x00000017, 0, 'N'],
                    'CKA_NEVER_EXTRACTABLE' :[0x00000018, 0, 'N'],
                    'CKA_KEY_TYPE' :[0x00000019, 0, 'N'],
                    'CKA_CERTIFICATE_TYPE' :[0x00000020, 0, 'N'],
                    'CKA_MODULUS_BITS' :[0x00000021, 0, 'N'],
                    'CKA_TRUSTED' :[0x00000030, 0, 'N'],
                    'CKA_ALWAYS_SENSITIVE' :[0x00000031, 0, 'N'],
                    'CKA_WRAP_WITH_TRUSTED' :[0x00000032, 0, 'N'],
                    'CKA_ALWAYS_AUTHENTICATE' :[0x00000033, 0, 'N'],
                    'CKA_VALUE' :[0x00000099, long_to_bytes(r), 'B'],
                   }
        
    return Certificate, PublicKey, PrivateKey, Data
    
    
if __name__ == '__main__':
    pass
    #print get_cert_list()
    #path = ['c:\\\\Users\\ktdev01\\AppData\\LocalLow\\NPKI\\yessign\\User\\cn=\xc1\xb6\xb4\xeb\xbc\xba(cho dae sung)0020049200606157221843,ou=WOORI,ou=personal4IB,o=yessign,c=kr\\']
    #x509_pa.x509_print(open(path[0]+'signCert.der', 'rb').read())
    #Certificate, PublicKey, PrivateKey, Data =  pki_paser(11, path[0], '!')
    
    
    
    
    
    

    
