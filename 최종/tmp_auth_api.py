#-*- coding: utf-8 -*-

import socket
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
import time, json, struct
import hashlib
import random
import pybase64
from Crypto.Cipher import PKCS1_OAEP

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS) 
unpad = lambda s : s[:-ord(s[len(s)-1:])]


def tmp_auth(SERIAL, EQP_UID, path_key):
    msg = json.dumps({'Time':time.time(), 'PK':SERIAL ,'EQP_UID':EQP_UID})
    result = Send_Data('Tmp_Auth', msg, path_key)
    if result['result'] == 'True':
        return (result['result'], result['authkey'], result['port'])
    else:
        return (result['result'], '', '')
    
def randomword(length):
    return ''.join(random.choice("ZXCVBNM<>?ASDFGHJKL:QWERTYUIOP{}!@#$%^&*()_+zxcvbnmasdfghjklqwertyuiop1234567890") for i in range(length)) 

def aes_encrypt(aes_key, aes_iv, raw ):
    cipher = AES.new( hashlib.sha256(aes_key).digest(), AES.MODE_CBC, hashlib.md5(aes_iv).digest() )
    return cipher.encrypt(pad(raw))
 
def aes_decrypt(aes_key, aes_iv, raw ):
    cipher = AES.new( hashlib.sha256(aes_key).digest(), AES.MODE_CBC, hashlib.md5(aes_iv).digest() )
    return unpad(cipher.decrypt(raw))
   
def Send_Data(method, data, path_key):
    aes_key = randomword(32)
    aes_iv = randomword(32)
    send_data = {'method':method, 'aes_key':aes_key, 'aes_iv':aes_iv}
    plan_send_data = json.dumps(send_data)
    keyPub = RSA.importKey(open(path_key, 'r').read())
    keyPub = PKCS1_OAEP.new(keyPub)
    enc_send_data = keyPub.encrypt(plan_send_data)
    enc_data = aes_encrypt(aes_key, aes_iv, data)
    last_data = json.dumps({'1':pybase64.standard_b64encode(enc_send_data), '2':pybase64.standard_b64encode(enc_data)})

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('127.0.0.1', 5050))
    s.send(struct.pack('I', len(last_data))+last_data)
    enc_recv_data = s.recv(struct.unpack('I', s.recv(4))[0]) 
    plan_recv_data = json.loads(aes_decrypt(aes_key, aes_iv, enc_recv_data))
    return plan_recv_data

        
if __name__ == '__main__':

    print tmp_auth('0052c48cf50dd88730a288e2b80ecc2c816aaf60b67936ccb177f4fe', '20170912182531842006', 'aaa_pub.pem')

    
    
    