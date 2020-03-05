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
import os
import multiprocessing
import threading
import json, struct

import customDB

from twisted.internet import reactor
import mitmproxy
import logging


import sys
import signal
import gevent
from gevent.server import StreamServer
from gevent.socket import create_connection, gethostbyname

# Changing the buffer_size and delay, you can improve the speed and bandwidth.
# But when buffer get to high or delay go too down, you can broke things
buffer_size = 4096
delay = 0.0001
#forward_to = ('127.0.0.01', 60000)

class Forward:
    def __init__(self):
        self.forward = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    def start(self, host, port):
        try:
            self.forward.connect((host, port))
            return self.forward
        except Exception, e:
            print e
            return False

class TheServer:
    input_list = []
    channel = {}
    
    def __init__(self, host, port, authkey, forward_to, tmp_auth):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((host, port))
        self.server.listen(1)
        self.authkey = authkey
        self.tmp_host, self.tmp_port = self.server.getsockname()
        self.forward_to = forward_to
        self.flage = False
        self.tmp_auth = tmp_auth
        self.fist_connet = True
        
        #print 'PID', os.getpid()
        
    def main_loop(self):
        threading.Thread(target=self.check_accept).start()
        
        self.input_list.append(self.server)
        while 1:
            #time.sleep(delay)
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
 
    def authentication_challenge(self, clientsock):
        if self.fist_connet == True:
            message = os.urandom(20)
            #print [message]
            clientsock.send(message)
            digest = hmac.new(self.authkey, message).digest()
            #print '1', digest.encode('hex')
            response = clientsock.recv(256)
            #print '2', response.encode('hex')
            if response == digest:
                self.fist_connet == False
            else:
                clientsock.close()
                return False
            return True
        
        else:
            return False
            

    def check_accept(self):
        if self.tmp_auth == True:
            cktime = 120
        else:
            cktime = 10
            
        for a in range(cktime):
            time.sleep(1)
            print a
            
            if self.flage == True:
                return
            elif a == cktime-1:
                print 'exit'
                self.on_close()
                #return
                #os.kill(os.getpid(), 9)
        return
        
    
    def on_accept(self):
        clientsock, clientaddr = self.server.accept()
        self.flage = True
        print clientaddr, "has connected"
        
        if self.authentication_challenge(clientsock) == False:
            return
        
        forward = Forward().start(self.forward_to[0], self.forward_to[1])
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

    def on_close(self):
        try:
            print self.s.getpeername(), "has disconnected"
            os.kill(os.getpid(), 9)
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
            os.kill(os.getpid(), 9)
        except:
            os.kill(os.getpid(), 9)
            
    def on_recv(self):
        #data = self.data
        # here we can parse and/or modify the data before send forward
        #print 'data len' , len(data)
        self.channel[self.s].send(self.data)




class PortForwarder(StreamServer):

    def __init__(self, listener, dest, authkey, tmp_auth, **kwargs):
        StreamServer.__init__(self, listener, **kwargs)
        self.dest = dest
        self.authkey = authkey
        self.tmp_auth = tmp_auth
        
    def handle(self, source, address): 
        try:
            dest = create_connection(self.dest)
        except IOError as ex:
            #log('%s:%s failed to connect to %s:%s: %s', address[0], address[1], self.dest[0], self.dest[1], ex)
            return

        forwarders = (gevent.spawn(forward, source, dest, self.authkey, self),gevent.spawn(forward, dest, source, self.authkey, self))
        gevent.joinall(forwarders)

    def close(self):
        if self.closed:
            sys.exit('Multiple exit signals received - aborting.')
        else:
            #log('Closing listener socket')
            StreamServer.close(self)


def forward(source, dest, server, authkey = None):
    source_address = '%s:%s' % source.getpeername()[:2]
    dest_address = '%s:%s' % dest.getpeername()[:2]
    try:
        if dest_address.split(':')[0] != '127.0.0.1':
            message = os.urandom(20)
            source.send(message)
            
            digest = hmac.new(authkey, message).digest()
            response = source.recv(256)
            if response == digest:
                pass
            else:
                if not server.closed:
                    server.close()

        while True:     
            try:
                data = source.recv(1024)
                #log('%s->%s: %r', source_address, dest_address, data)
                if not data:
                    break
                dest.sendall(data)
            except KeyboardInterrupt:
                # On Windows, a Ctrl-C signal (sent by a program) usually winds
                # up here, not in the installed signal handler.
                if not server.closed:
                    server.close()
                break
            except socket.error:
                if not server.closed:
                    server.close()
                break
    finally:
        source.close()
        dest.close()
        server = None


def multiprocess_start(authkey, forward_to, tport, tmp_auth):
    try:
        server = PortForwarder('0.0.0.0:%s'%tport, forward_to, authkey, tmp_auth) 
        gevent.signal(signal.SIGTERM, server.close)
        gevent.signal(signal.SIGINT, server.close)
        server.start()
        gevent.wait()
    except Exception, e:
        print 'multiprocess_start', e
        os.kill(os.getpid(), 9)

def mitmproxy_ssh_main(H_ip, P_port,  send_end, authkey, PROTOCOL, CMD_UID, server_id, CSN, NAME, tmp_auth):
    try:
        #send_end = None,
        (opts, _) = mitmproxy.ssh_proxy_option_parser(P_port, 0)
        opts.host = H_ip
        opts.port = P_port
        opts.localport = 0
        opts.logfile = time.strftime("%Y%m%d_%H%M%S", time.localtime())+'_'+CSN+'_'+H_ip+'_ssh_.log'
        opts.aclip = '127.0.0.1'
        opts.PROTOCOL = PROTOCOL
        opts.CMD_UID = CMD_UID
        
        
        opts.server_id = server_id
        opts.CSN = CSN
        opts.tmp_auth = tmp_auth
        opts.EQ_NAME = NAME
        if opts.debug:
            logging.basicConfig(filename='ssh.log',filemode='w',format='%(levelname)s:%(message)s',level=logging.DEBUG)
        sys.stderr.write('Server running on localhost:%d...\n' % (opts.localport))
        factory = mitmproxy.SSHServerFactory(opts)
        ser = reactor.listenTCP(opts.localport, factory, interface='127.0.0.1')
        send_end.send(ser.getHost().port)
        sys.stderr.write('Server running on localhost:%d...\n' % (ser.getHost().port))
        reactor.run()
        #reactor.run()
        #p = multiprocessing.Process( target=reactor.run )
        #p.daemon = True
        #p.start()
        #return ser.getHost().port
    except Exception, e:
        print 'mitmproxy_ssh_main', e
        #p.terminate()
        os.kill(os.getpid(), 9)
    #sys.exit(mitmproxy.exit_code.pop())

def setup(authkey, server_id, CSN, tmp_auth = False) :
    
    #print server_id
    #sql_tmp = "SELECT target_ip, target_port FROM `access_list` WHERE `server_id` LIKE '%s'"%server_id
    #infor = mysql_conn(sql_tmp)[0]
    #ip_tmp = infor[0]
    #port_tmp = infor[1] 
    sql_tmp = "SELECT IP, L4PORT, PROTOCOL, CMD_UID, NAME FROM KTWIZSTICK.TTP_EQP WHERE `EQP_UID`='%s';"%server_id
    IP, L4PORT, PROTOCOL, CMD_UID, NAME =customDB.mysql_conn(sql_tmp)[0]
    
    #print IP, L4PORT, PROTOCOL, CMD_UID, NAME
    
    #sql_tmp = "SELECT CMD FROM KTWIZSTICK.TTP_CMD_SET where CMD_UID = '%s';"%CMD_UID
    #CMD =customDB.mysql_conn(sql_tmp)[0]
    
    #ip_tmp = '210.92.37.189'
    #port_tmp = 60000
    
    recv_end, send_end = multiprocessing.Pipe(False)
    sshproxy =  multiprocessing.Process(target=mitmproxy_ssh_main, args=(IP,  int(L4PORT), send_end, authkey,  PROTOCOL, CMD_UID, server_id, CSN, NAME, tmp_auth) )
    #sshproxy.daemon = True
    sshproxy.start()
    
    ssh_porxy_port = recv_end.recv()
    
    #ssh_porxy_port = mitmproxy_ssh_main(IP,  int(L4PORT), authkey,  PROTOCOL, CMD_UID, server_id, CSN, NAME, tmp_auth)

    #port = multiprocess_start(authkey, ('127.0.0.1', int(ssh_porxy_port)), tmp_auth )
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('127.0.0.1', 0))
    thost, tport = server.getsockname()
    server.close()
        

    p = multiprocessing.Process(target=multiprocess_start, args=(authkey, ('127.0.0.1', int(ssh_porxy_port)), tport, tmp_auth))
    #p.daemon = True
    p.start()
    
    return str(tport)

