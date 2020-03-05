#!/usr/bin/python
#
# Copyright (c) 2014-2015 Sylvain Peyrefitte
#
# This file is part of rdpy.
#
# rdpy is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#

"""
RDP proxy with Man in the middle capabilities
Save RDP events in output RSR file format
RSR file format can be read by rdpy-rsrplayer.py
               ----------------------------
Client RDP -> | ProxyServer | ProxyClient | -> Server RDP
              ----------------------------
                   | Record Session |
                   -----------------
"""

import sys, os, getopt

from rdpy.core import log, error, rss
from rdpy.protocol.rdp import rdp

import threading

'''
import qt4reactor
try:
    qt4reactor.install()
except:
    pass
'''

from scancode import scancodeToChar
#from PyQt4 import QtCore, QtGui


from twisted.internet import reactor


import hmac
import time
#from rdpy.ui.qt4 import RDPBitmapToQtImage
import socket
from multiprocessing import Process
import hashlib
#import multiprocessing
import customDB


import redis
import cjson
#import pybase64



keyboard_buffer = ''
SESSION_ID = ''
User_Name = ''
EQP_UID = ''
screen_shot = False

log._LOG_LEVEL = log.Level.INFO

#r = redis.StrictRedis(host='localhost', port=6379, db=0)
#pool = redis.ConnectionPool(host='localhost', port=6379, db=0, password=None, socket_timeout=None)
pool = redis.ConnectionPool(connection_class=redis.UnixDomainSocketConnection, path='/var/run/redis/redis.sock', db=0)
r = redis.Redis(connection_pool=pool)
#p = r.pubsub()
# LOG_TYPE 30, 31, 32, 33, 34

def GEN_SESSION_ID(data):
    return hashlib.sha1(data).hexdigest()

class ProxyServer(rdp.RDPServerObserver):
    """
    @summary: Server side of proxy
    """
    def __init__(self, controller, target, clientSecurityLevel, rssRecorder, Return_Msg, queue):
        """
        @param controller: {RDPServerController}
        @param target: {tuple(ip, port)}
        @param rssRecorder: {rss.FileRecorder} use to record session
        """
        rdp.RDPServerObserver.__init__(self, controller)
        self._target = target
        self._client = None
        self._rss = rssRecorder
        self._clientSecurityLevel = clientSecurityLevel
        
        self.first_flag = True
        
        self.Return_Msg = Return_Msg
        
        self._ouputDir = Return_Msg['ouputDirectory']
        self.authkey = Return_Msg['authkey']
        self.auth_time = Return_Msg['auth_time']
        
        self.RDP_IN_YN = int(Return_Msg['RDP_IN_YN'])
        
        self.queue = queue
        
        self.continuity = 0
        #self.EQP_UID = EQP_UID
        #self.PK = PK
        #self.EQP_NAME = EQP_NAME
        #self.clientaddr_ip = clientaddr_ip
        #self.tmp_auth = tmp_auth
        
    def ck_continuity(self, old):
        new = time.time()
        if new - old > 3:
            self.continuity = new
            return True
        else:
            return False
        
    def setClient(self, client):
        """
        @summary: Event throw by client when it's ready
        @param client: {ProxyClient}
        """
        self._client = client
        
    def onReady(self):
        """
        @summary:  Event use to inform state of server stack
                    First time this event is called is when human client is connected
                    Second time is after color depth nego, because color depth nego
                    restart a connection sequence
        @see: rdp.RDPServerObserver.onReady
        """
        if self._client is None:
            #try a connection
            domain, username, password = self._controller.getCredentials()
            
            print self.auth_time, [self.authkey.encode('hex')[0:99]], [username]
            #print self._controller.getHostname()
            
            self.Return_Msg['Hostname'] = self._controller.getHostname()
            
            if self.first_flag == False:
                self.onClose()
                print "self.first_flag "
                return
            if time.time() - self.auth_time > 60:
                self.onClose()
                print "time.time() - self.auth_time"
                return
            if self.authkey.encode('hex')[0:99] != username:
                print "self.authkey.encode('hex')[0:99] != username"
                self.onClose()          
                return 
            
            self.first_flag = False
            username = ''
            
            
            self._rss.credentials(username, password, domain, self._controller.getHostname())
            
            width, height = self._controller.getScreen()
            
            #width
            #height
            #print  self._controller.getColorDepth()
            
            self._rss.screen(width, height, 8)
            
            reactor.connectTCP(self._target[0], int(self._target[1]), ProxyClientFactory(self, width, height, domain, username, password,self._clientSecurityLevel, self.Return_Msg, self.queue))
    
    
    def exit_tmp(self):
        print 'exit',os.getpid()
        time.sleep(5)
        '''
        data = {'type':'TEXT', 'Sub_type':'End Log', 'data':(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()), 'LogOut', 'BIN', 102,self.Return_Msg['SESSION_ID'],self.Return_Msg, None)}
        while True:
            tmp = r.lpush(self.Return_Msg['SESSION_ID'], 'FFAFF'+cjson.encode(data))  
            if tmp == 1:
                break
            time.sleep(0.5)
         
        while True:
            tmp = r.lpush(self.Return_Msg['SESSION_ID'], 'FFAFF'+cjson.encode({'type':'close', 'Sub_type':'make video','data':self.Return_Msg}))
            if tmp == 1:
                break
            time.sleep(0.5)
        '''
        os.kill(os.getpid(), 9)

    def onClose(self):
        print "onClose 2", self._target[0], int(self._target[1]), self._client
        """
        @summary: Call when human client close connection
        @see: rdp.RDPServerObserver.onClose
        """
        #end scenario
        self._rss.close()
        

        
        #close network stack
        if self._client is None:
            return
        self._client._controller.close()
        
        threading.Thread(target=self.exit_tmp).start()
        '''

        '''  
               
        
    def onKeyEventScancode(self, code, isPressed, isExtended):
        global screen_shot
        """
        @summary: Event call when a keyboard event is catch in scan code format
        @param code: {integer} scan code of key
        @param isPressed: {boolean} True if key is down
        @param isExtended: {boolean} True if a special key
        @see: rdp.RDPServerObserver.onKeyEventScancode
        """
        
        global keyboard_buffer
        if isPressed :
            keyboard_buffer += scancodeToChar(code)+','
            
        if code == 28 and screen_shot:
            #print keyboard_buffer
            lentmp = len(keyboard_buffer)
            if  lentmp > 1000:
                keyboard_buffer = keyboard_buffer[0:999]
            if lentmp != 0:
                data = {'type':'TEXT', 'Sub_type':'keybord', 'data':(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()), 'TLG_ACT_IN_LOG', 'TEXT', 31, keyboard_buffer[0:-1],self.Return_Msg, None)}
                r.lpush(self.Return_Msg['SESSION_ID'], 'FFAFF'+cjson.encode(data))            
            
            keyboard_buffer = ''
            if self.ck_continuity(self.continuity):
                tmp = self._ouputDir+'/'+str(time.time())+"_enter.jpg"
                data = {'type':'PrtScn', 'Sub_type':'keybord_enter', 'data':(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()), 'TLG_ACT_IN_LOG', 'PHOTO', 31,'keybord_enter',self.Return_Msg, tmp)}
                r.lpush(self.Return_Msg['SESSION_ID'], 'FFAFF'+cjson.encode(data))
                
                
                
                
     
               
            
        #print hex(code), code, isPressed,isExtended
        #print 
        if self._client is None:
            return
        self._client._controller.sendKeyEventScancode(code, isPressed, isExtended)
        
    
    def onKeyEventUnicode(self, code, isPressed):
        """
        @summary: Event call when a keyboard event is catch in unicode format
        @param code: unicode of key
        @param isPressed: True if key is down
        @see: rdp.RDPServerObserver.onKeyEventUnicode
        """
        #print code, isPressed
        if self._client is None:
            return
        self._client._controller.sendKeyEventUnicode(code, isPressed)
        self._rss.keyUnicode(code, isPressed)
    
    def delay_shot(self, tmp):
        time.sleep(2)
        #_buffer.save(tmp, 'jpg', 50)
        tmp = self._ouputDir+'/'+str(time.time())+"_delay_shot.jpg"
        data = {'type':'PrtScn', 'Sub_type':'delay_shot', 'data':(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()), 'TLG_ACT_IN_LOG', 'PHOTO', 33,'delay_shot',self.Return_Msg, tmp)}
        r.lpush(self.Return_Msg['SESSION_ID'], "screen_shot:"+tmp)
        #self.queue.put()
        
    def onPointerEvent(self, x, y, button, isPressed):
        global screen_shot
        
        """
        @summary: Event call on mouse event
        @param x: {int} x position
        @param y: {int} y position
        @param button: {int} 1, 2 or 3 button
        @param isPressed: {bool} True if mouse button is pressed
        @see: rdp.RDPServerObserver.onPointerEvent
        """
        
        #print x, y, button, isPressed
        #button 1,2,3
        if  self.RDP_IN_YN == 1 and isPressed and screen_shot and self.ck_continuity(self.continuity):
            tmp = self._ouputDir+'/'+str(time.time())+"_click.jpg"
            data = {'type':'PrtScn', 'Sub_type':'click', 'data':(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()), 'TLG_ACT_IN_LOG', 'PHOTO', 30,'mouse_click',self.Return_Msg, tmp)}
            r.lpush(self.Return_Msg['SESSION_ID'], 'FFAFF'+cjson.encode(data))          
                    
            #threading.Thread(target=self.delay_shot, args = (tmp, )).start()
            
            
        if self._client is None:
            return
        self._client._controller.sendPointerEvent(x, y, button, isPressed)
        
        
        
class ProxyServerFactory(rdp.ServerFactory):
    """
    @summary: Factory on listening events
    """
    def __init__(self, target, ouputDir, privateKeyFilePath, certificateFilePath, clientSecurity,  Return_Msg, queue):
        """
        @param target: {tuple(ip, prt)}
        @param privateKeyFilePath: {str} file contain server private key (if none -> back to standard RDP security)
        @param certificateFilePath: {str} file contain server certificate (if none -> back to standard RDP security)
        @param clientSecurity: {str(ssl|rdp)} security layer use in client connection side
        """
        
        rdp.ServerFactory.__init__(self, 16, privateKeyFilePath, certificateFilePath)
        self._target = target
        self._ouputDir = ouputDir
        self._clientSecurity = clientSecurity
        #use produce unique file by connection
        self._uniqueId = 0
        self.auth_time  = time.time()
        
        self.Return_Msg = Return_Msg
        self.Return_Msg['auth_time'] = time.time()
        self.queue = queue
        
        
    def buildObserver(self, controller, addr):
        """
        @param controller: {rdp.RDPServerController}
        @param addr: destination address
        @see: rdp.ServerFactory.buildObserver
        """
        self._uniqueId += 1
        return ProxyServer(controller, self._target, self._clientSecurity, rss.createRecorder(os.path.join(self._ouputDir, "%s_%s_%s.rss"%(time.strftime('%Y%m%d%H%M%S'), addr.host, self._uniqueId))), self.Return_Msg, self.queue)



class ProxyClient(rdp.RDPClientObserver):
    
    """
    @summary: Client side of proxy
    """
    def __init__(self, controller, server, _width, _height, Return_Msg, queue):
        """
        @param controller: {rdp.RDPClientController}
        @param server: {ProxyServer} 
        """
        #global _buffer
        rdp.RDPClientObserver.__init__(self, controller)
        self._server = server
        
        
        #_buffer = QtGui.QImage(_width, _height, QtGui.QImage.Format_RGB16)
        #self.flage = True
        
        self.Return_Msg = Return_Msg
        self._ouputDir = Return_Msg['ouputDirectory']
        self.sleeptime = int(Return_Msg['RDP_OUT_TIMER'])
        
        self._width = _width
        self._height =  _height
         
        #self.EQP_UID = EQP_UID
        #self.PK = PK
        #self.EQP_NAME = EQP_NAME
        #self.clientaddr_ip = clientaddr_ip
        #self.tmp_auth = tmp_auth
        self.queue = queue
        
    def onReady(self):
        print 'onReady'
        """
        @summary:  Event use to signal that RDP stack is ready
                    Inform ProxyServer that i'm connected
        @see: rdp.RDPClientObserver.onReady
        """
        self._server.setClient(self)
        #maybe color depth change
        
        
        self._server._controller.setColorDepth(self._controller.getColorDepth())
        
        
        
        #reids_test_q2.gen_screen_shot(self.Return_Msg['SESSION_ID'], self._width, self._height, self.Return_Msg, self.sleeptime)
        MESSAGE = (self.Return_Msg['SESSION_ID'], self._width, self._height, self.Return_Msg, self.sleeptime)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(cjson.encode(('RDP', MESSAGE)), ('127.0.0.1', 12345))
 
        
        #self.t = threading.Thread(target=self.popjpg)
        #self.t.setDaemon(True)
        #self.t.start()
        
    def onSessionReady(self):
        global screen_shot
        """
        @summary: Windows session is ready
        @see: rdp.RDPClientObserver.onSessionReady
        """
        print 'onSessionReady'
        
        #print self._server._controller.getCredentials()
        #self.queue.put((time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()), 'LogIn', 'BIN', 101,self.Return_Msg['SESSION_ID'],self.Return_Msg, None))
        
        
        self._gotdata = True
        def check():
            print time.time(), "reactor.callLater(300, check)"
            if self._gotdata:
                self._gotdata = False
                reactor.callLater(120, check)
            else:
                self.onClose()
        check()
        
        if screen_shot == False:
            screen_shot = True
            data = {'type':'TEXT', 'Sub_type':'Start Log', 'data':(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()), 'LogIn', 'BIN', 101,self.Return_Msg['SESSION_ID'],self.Return_Msg, None)}
            r.lpush(self.Return_Msg['SESSION_ID'], 'FFAFF'+cjson.encode(data))    
            
        
        
    def onClose(self):
        print 'onClose 1'
        """
        @summary: Event inform that stack is close
        @see: rdp.RDPClientObserver.onClose
        """
        #end scenario

        '''
        data = {'type':'TEXT', 'Sub_type':'End Log', 'data':(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()), 'LogOut', 'BIN', 102,self.Return_Msg['SESSION_ID'],self.Return_Msg, None)}
        
        while True:
            tmp = r.lpush(self.Return_Msg['SESSION_ID'], 'FFAFF'+cjson.encode(data))  
            if tmp == 1:
                break
            time.sleep(0.5)
         
        while True:
            tmp = r.lpush(self.Return_Msg['SESSION_ID'], 'FFAFF'+cjson.encode({'type':'close', 'Sub_type':'make video','data':self.Return_Msg}))
            if tmp == 1:
                break
            time.sleep(0.5)
        '''
        
        data = {'type':'TEXT', 'Sub_type':'End Log', 'data':(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()), 'LogOut', 'BIN', 102,self.Return_Msg['SESSION_ID'],self.Return_Msg, None)}
        
        r.lpush(self.Return_Msg['SESSION_ID'], 'FFAFF'+cjson.encode(data))
        
        r.lpush(self.Return_Msg['SESSION_ID'], 'FFAFF'+cjson.encode({'type':'close', 'Sub_type':'make video','data':self.Return_Msg}))
        
        self._server._rss.close()
        self._server._controller.close()
        reactor.stop()
        
        print 'close end'
        
        os.kill(os.getpid(), 9)
     
        
            
    def onUpdate(self, destLeft, destTop, destRight, destBottom, width, height, bitsPerPixel, isCompress, data):
        
        #global _buffer
        """
        @summary: Event use to inform bitmap update
        @param destLeft: {int} xmin position
        @param destTop: {int} ymin position
        @param destRight: {int} xmax position because RDP can send bitmap with padding
        @param destBottom: {int} ymax position because RDP can send bitmap with padding
        @param width: {int} width of bitmap
        @param height: {int} height of bitmap
        @param bitsPerPixel: {int} number of bit per pixel
        @param isCompress: {bool} use RLE compression
        @param data: {str} bitmap data
        @see: rdp.RDPClientObserver.onUpdate
        """
        self._gotdata = True    
        #self.flage = False
        #image  = RDPBitmapToQtImage(width, height, bitsPerPixel, isCompress, data)
        
        #with QtGui.QPainter(_buffer) as qp:
               #qp.drawImage(destLeft, destTop, image, 0, 0, destRight - destLeft + 1, destBottom - destTop + 1)
        
        
        
        #r.lpush('win', cjson.encode((destLeft, destTop, destRight, destBottom, width, height, bitsPerPixel, isCompress, data)))
        
        
        r.lpush(self.Return_Msg['SESSION_ID'], (destLeft, destTop, destRight, destBottom, width, height, bitsPerPixel, isCompress, data.encode('hex')))
        #r.publish(self.Return_Msg['SESSION_ID'], (destLeft, destTop, destRight, destBottom, width, height, bitsPerPixel, isCompress, data.encode('hex')))
        #self._server._rss.update(destLeft, destTop, destRight, destBottom, width, height, bitsPerPixel, rss.UpdateFormat.BMP if isCompress else rss.UpdateFormat.RAW, data)
        
        self._server._controller.sendUpdate(destLeft, destTop, destRight, destBottom, width, height, bitsPerPixel, isCompress, data)

class ProxyClientFactory(rdp.ClientFactory):
    """
    @summary: Factory for proxy client
    """
    def __init__(self, server, width, height, domain, username, password, security, Return_Msg, queue):
        """
        @param server: {ProxyServer}
        @param width: {int} screen width
        @param height: {int} screen height
        @param domain: {str} domain session
        @param username: {str} username session
        @param password: {str} password session
        @param security: {str(ssl|rdp)} security level
        """
        self._server = server
        self._width = width
        self._height = height
        self._domain = domain
        self._username = username
        self._password = password
        self._security = security
        
        self.Return_Msg = Return_Msg
        self.queue = queue
        
    def buildObserver(self, controller, addr):
        """
        @summary: Build observer
        @param controller: rdp.RDPClientController
        @param addr: destination address
        @see: rdp.ClientFactory.buildObserver
        @return: ProxyClient
        """
        
        #set screen resolution
        controller.setScreen(self._width, self._height)
        #set credential
        controller.setDomain(self._domain)
        controller.setUsername(self._username)
        controller.setPassword(self._password)
        controller.setSecurityLevel(self._security)
        controller.setPerformanceSession()
        return ProxyClient(controller, self._server, self._width, self._height, self.Return_Msg, self.queue)
    
    
def help():
    """
    @summary: Print help in console
    """
    print """
    Usage:  rdpy-rdpmitm.py -o output_directory target
            [-l listen_port default 3389] 
            [-k private_key_file_path (mandatory for SSL)] 
            [-c certificate_file_path (mandatory for SSL)] 
            [-o output directory for recoded files] 
            [-r RDP standard security (XP or server 2003 client or older)] 
            [-n For NLA Client authentication (need to provide credentials)] 
    """

def parseIpPort(interface, defaultPort = "3389"):
    if ':' in interface:
        return interface.split(':')
    else:
        return interface, defaultPort

def setup(authkey, PK, Return_Msg, queue, clientaddr_ip = False, tmp_auth = False) :

    #PROTOCOL = Return_Msg['PROTOCOL']
    #CMD_UID = Return_Msg['CMD_UID']
    #EQP_NAME = Return_Msg['NAME']
    
    target = (Return_Msg['IP'], int(Return_Msg['L4PORT']))
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('127.0.0.1', 0))
    thost, listen = server.getsockname()
    server.close()
    
    rdpproxy =  Process(target=start, args=(listen, target, authkey, PK, Return_Msg, clientaddr_ip, tmp_auth, queue) )
    rdpproxy.start()
    return str(listen)

def start(listen, target, authkey, PK, Return_Msg, clientaddr_ip, tmp_auth, queue):
    try:
        print '[RDP start]', os.getpid()
        clientSecurity = rdp.SecurityLevel.RDP_LEVEL_SSL   
        ouputDirectory = 'data'
        privateKeyFilePath = 'server.key'
        certificateFilePath = 'server.crt'
        SESSION_ID = GEN_SESSION_ID(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())+str(authkey))
        ouputDirectory ='/WIZSTICK_LOG/RDP/'+time.strftime("%Y", time.localtime())+'/'+time.strftime("%m%d", time.localtime())+'/'+SESSION_ID
        if os.path.exists(ouputDirectory) == False:
            os.makedirs(ouputDirectory)   
        Return_Msg['SESSION_ID'] = SESSION_ID
        Return_Msg['authkey'] = authkey
        Return_Msg['PK'] = PK
        Return_Msg['clientaddr_ip']= clientaddr_ip
        Return_Msg['tmp_auth'] = tmp_auth
        Return_Msg['ouputDirectory'] = ouputDirectory
        #customDB.mysql_log_insert(mypool, (strftime("%Y-%m-%d %H:%M:%S", localtime()), server_id,EQ_NAME, EQ_IP,CSN,'',ssh_login_username, 102, 0, 'LogOut', 'TEXT'), SESSION_ID)
        #target = ('192.168.2.167', 3389)
        reactor.listenTCP(int(listen), ProxyServerFactory(target, ouputDirectory, privateKeyFilePath, certificateFilePath, clientSecurity, Return_Msg, queue))
        reactor.run()
    except Exception, e:
        print '[start]', e
        os.kill(os.getpid(), 9)
    



    
    
    
if __name__ == '__main__':
    listen = "3381"
    privateKeyFilePath = None
    certificateFilePath = None
    ouputDirectory = None
    #for anonymous authentication
    clientSecurity = rdp.SecurityLevel.RDP_LEVEL_SSL
    
    '''
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hl:k:c:o:rn")
    except getopt.GetoptError:
        help()
    for opt, arg in opts:
        if opt == "-h":
            help()
            sys.exit()
        elif opt == "-l":
            listen = arg
        elif opt == "-k":
            privateKeyFilePath = arg
        elif opt == "-c":
            certificateFilePath = arg
        elif opt == "-o":
            ouputDirectory = arg
        elif opt == "-r":
            clientSecurity = rdp.SecurityLevel.RDP_LEVEL_RDP
        elif opt == "-n":
            clientSecurity = rdp.SecurityLevel.RDP_LEVEL_NLA
            
    if ouputDirectory is None or not os.path.dirname(ouputDirectory):
        log.error("%s is an invalid output directory"%ouputDirectory)
        help()
        sys.exit()
    '''
    
    ouputDirectory = 'data'
    privateKeyFilePath = 'server.key'
    certificateFilePath = 'server.crt'
    clientSecurity =  rdp.SecurityLevel.RDP_LEVEL_SSL
    
    target = ('192.168.2.167', 3389)
    #parseIpPort(args[0])
    reactor.listenTCP(int(listen), ProxyServerFactory(target, ouputDirectory, privateKeyFilePath, certificateFilePath, clientSecurity))
    reactor.run()
    
    #mstsc /v:127.0.0.1:3381