import string
import random
import hashlib
from M2Crypto.EVP import MessageDigest
import binascii
import struct
import time

def id_generator(size=6, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))

data = "a"*16
a,b = divmod(len(data),16)
print a, b

def add_padding(padding, data):
    print padding, id_generator(padding)
    result_data = binascii.unhexlify(data.encode('hex'))+binascii.unhexlify(id_generator(padding).encode('hex'))+struct.pack('B',padding)
    print len(result_data), result_data.encode('hex')

#if a >= 0 and b !=0:
padding = 15-b
if padding == 0:
    print 'a'
    padding = 16
    add_padding(padding, data)
else:
    print 'b'
    add_padding(padding, data)


for a in range(6000):
    c_time = time.time()
    time.sleep(0.001)
    print c_time, (struct.pack('>f',c_time)).encode('hex'), (struct.pack('>d',c_time)).encode('hex')
    
#elif a > 0 and b == 0:
#    print 'c'
#    padding = 15
#    aa(padding, data)
    
    
'''
m = hashlib.md5()
m.update("1")
#m.update(" the spammish repetition")
b = m.copy()
print m.hexdigest()
print b.hexdigest()
m.update("1")
b.update("1")

print b.hexdigest()
print m.hexdigest()
m = hashlib.md5('11')
print m.hexdigest()

dgst2 = MessageDigest('md5')
dgst2.update('1')

print 'b',dgst2.digest().encode('hex')
dgst2.update('1')
print 'b',dgst2.digest().encode('hex')
dgst2.update('1')
print 'a',dgst2.final().encode('hex')
'''