#!/usr/bin/python
# This is a simple port-forward / proxy, written using only the default python
# library. If you want to make a suggestion or fix something you can contact-me
# at voorloop_at_gmail.com
# Distributed over IDC(I Don't Care) license
import socket
import select
import time
import sys
import hmac

import struct
import json, struct

from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, long_to_bytes

import re
re_find_hex = re.compile("hexValue='\w*'")

# Changing the buffer_size and delay, you can improve the speed and bandwidth.
# But when buffer get to high or delay go too down, you can broke things
buffer_size = 4096
delay = 0.0001
forward_to = ('210.92.37.189', 7070)

class Forward:
    def __init__(self):
        self.forward = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
    def start(self, host, port, authkey):
        try:
            self.forward.connect((host, port))
            message = self.forward.recv(20)
            print [message]
            #authkey = 'AA'
            digest = hmac.new(authkey, message).digest()
            self.forward.send(digest)
            
            return self.forward
        except Exception, e:
            print e
            return False

class TheServer:
    input_list = []
    channel = {}

    def __init__(self, host, port, server_id, forward_to_ip, forward_to_port, authkey):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((host, port))
        self.server.listen(3)
        self.tmp_host, self.tmp_port = self.server.getsockname()
        self.server_id = server_id
        self.forward_to_ip = forward_to_ip
        self.forward_to_port = forward_to_port
        self.authkey = authkey

    def main_loop(self):
        self.input_list.append(self.server)
        while 1:
            time.sleep(delay)
            ss = select.select
            inputready, outputready, exceptready = ss(self.input_list, [], [])
            for self.s in inputready:
                if self.s == self.server:
                    self.on_accept()
                    break

                self.data = self.s.recv(buffer_size)
                if len(self.data) == 0:
                    self.on_close()
                    break
                else:
                    self.on_recv()
    
    def vid_extraction(self, tbs):
        result = {}
        if tbs.subjAltNameExt:
            tmp = ''
            #logger.info("\tSubject Alternative Name: is_critical: %s" %tbs.subjAltNameExt.is_critical)
            san = tbs.subjAltNameExt.value
            for component_type, name_list in san.values.items():
                tmp = name_list[0]
                #logger.info("\t\t%s: %s" % (component_type, ",".join(name_list)))
            
            if tmp != '':
                result.update({'hex':re_find_hex.findall(tmp)})
            return result
        return False
                   
    def authentication(self):
        return (self.forward_to_ip, self.forward_to_port, self.authkey)
        
        
    def on_accept(self):
        
        clientsock, clientaddr = self.server.accept()
        print clientaddr, "has connected"
        
        
        forward_to_ip, forward_to_port, authkey = self.authentication()
        

        
        forward = Forward().start(forward_to_ip, forward_to_port, authkey)
        if forward:
       
            print clientaddr, "has connected"
            self.input_list.append(clientsock)
            self.input_list.append(forward)
            self.channel[clientsock] = forward
            self.channel[forward] = clientsock
            
        else:
            print "Can't establish connection with remote server.",
            print "Closing connection with client side", clientaddr
            clientsock.close()
            raise NameError('End')

    def on_close(self):
        print self.s.getpeername(), "has disconnected"
        #remove objects from input_list
        self.input_list.remove(self.s)
        self.input_list.remove(self.channel[self.s])
        out = self.channel[self.s]
        # close the connection with client
        self.channel[out].close()  # equivalent to do self.s.close()
        # close the connection with remote server
        self.channel[self.s].close()
        # delete both objects from channel dict
        del self.channel[out]
        del self.channel[self.s]
        raise NameError('End')

    def on_recv(self):
        data = self.data
        # here we can parse and/or modify the data before send forward
        print 'data len' , len(data)
        self.channel[self.s].send(data)

if __name__ == '__main__':
    server = TheServer('127.0.0.1', 9090,  'wiz stick')
    try:
        server.main_loop()
    except KeyboardInterrupt:
        print "Ctrl C - Stopping server"
        sys.exit(1)
    except Exception, e:
        print e
        
        
    #Xshell.exe -url ssh://ktwiz:@127.0.0.1:9090
    #putty.exe telnet://host[:port]/