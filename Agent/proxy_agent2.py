#-*- coding: utf-8 -*-

import socket
import select
import time
import sys
import hmac
import struct
import wiztoken_UI as wiztoken
#import ctypes

# Changing the buffer_size and delay, you can improve the speed and bandwidth.
# But when buffer get to high or delay go too down, you can broke things
buffer_size = 4096
delay = 0.0001


class Forward:
    def __init__(self):
        self.forward = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
    def start(self, host, port, authkey):
        try:
            self.forward.connect((host, port))
            message = self.forward.recv(20)
            #print [message]
            #authkey = 'AA'
            #print authkey
            digest = hmac.new(authkey, message).digest()
            #print digest
            self.forward.send(digest)
            return self.forward
        except Exception, e:
            print 'Forward',e
            return False

class TheServer:
    input_list = []
    channel = {}

    def __init__(self, host, port, CSN, forward_to_ip, forward_to_port, authkey):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((host, port))
        self.server.listen(1)
        self.tmp_host, self.tmp_port = self.server.getsockname()
        
        self.CSN = CSN
        self.forward_to_ip = forward_to_ip
        self.forward_to_port = forward_to_port
        self.authkey = authkey
        
        self.time_ck= time.time()
        self.wiz_stick = wiztoken.wizstick()
        self.interval = 30#60 * 5
        
        
    def wizstick_ck(self):
        if wiztoken.set() == False:
            return (False, "")    
        result, ChID = self.wiz_stick.bioOpenin()
        if result[0] != 0:
            return (False, "")      
        result, CSN = self.wiz_stick.bioGetCSN(ChID)
        if result[0] != 0:
            return (False, "")           
        result, wiz_data = self.wiz_stick.bioCloseOut(ChID)       
        if result[0] != 0:
            return (False, "")      
        if  CSN != self.CSN:
            return (False, "CSN")
        return (True, '')

    def wizstick_connet(self):
        if time.time() - self.time_ck  > self.interval  and self.CSN != '':
            self.time_ck = time.time()
            tmp_result = self.wizstick_ck()
            #print tmp_result
            if tmp_result[0] ==  False:
                if tmp_result[1] != "":
                    raise NameError('End CSN no')   
                    #self.MessageBox(None, u'연결된  Wiz Stick과 세션을 승인한 Wiz Stick이 일치하지 않아 연결을 종료합니다.', 'KT Wiz Stick', 0)
                else:
                    raise NameError('End no wizstick')   
                    #self.MessageBox(None, u'Wiz Stick 연결이 해제되어 연결을 종료합니다.', 'KT Wiz Stick', 0)
                    
                raise NameError('End wizstick_ck')        

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
                self.on_recv()
                
                '''
                if len(self.data) == 0:
                    self.on_close()
                    break
                
                else:
                    self.on_recv()
                
                '''
                #self.wizstick_connet()

    def authentication(self):
        return (self.forward_to_ip, self.forward_to_port, self.authkey)

    def on_accept(self):
        clientsock, clientaddr = self.server.accept()
        #print clientaddr, "has connected"
        forward_to_ip, forward_to_port, authkey = self.authentication()
        forward = Forward().start(forward_to_ip, forward_to_port, authkey)
        if forward:
            #print clientaddr, "has connected"
            self.input_list.append(clientsock)
            self.input_list.append(forward)
            self.channel[clientsock] = forward
            self.channel[forward] = clientsock
        else:
            #print "Can't establish connection with remote server.",
            #print "Closing connection with client side", clientaddr
            clientsock.close()
            raise NameError('End1')

    def on_close(self):
        #print self.s.getpeername(), "has disconnected"
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
        sys.exit(1)
        
        raise NameError('End2')
        
        
        
    def on_recv(self):
        #data = self.data
        #print self.data
        # here we can parse and/or modify the data before send forward
        #print 'data len' , len(data)
        self.channel[self.s].sendall(self.data)
        

if __name__ == '__main__':
    server = TheServer('127.0.0.1', 9090,  'wiz stick')
    try:
        server.main_loop()
    except KeyboardInterrupt:
        print "Ctrl C - Stopping server"
        sys.exit(1)
    except Exception, e:
        print 'forward',e
        
        #MessageBox = ctypes.windll.user32.MessageBoxA
        #MessageBox(None, str(e), 'KT Wiz Stick', 0)
        
        
    #Xshell.exe -url ssh://ktwiz:@127.0.0.1:9090
    #putty.exe telnet://host[:port]/