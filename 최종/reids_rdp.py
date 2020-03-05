# -*- coding: utf-8 -*-

import redis
from PyQt4 import QtGui#, QtCore
#from rdpy.ui.qt4 import RDPBitmapToQtImage
import time
#import cjson
import json
import customDB
import socket
from multiprocessing import Process
import sys
import threading
import rle

import gevent
from gevent import socket




proc_list = {}

class GeventConnection(redis.Connection):
  
    def _connect(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.socket_timeout)
        sock.connect((self.host, self.port))
        return sock
    
def gen_screen_shot(name_space, _width, _height, Return_Msg, sleep_time):    
    try:
        pool = redis.ConnectionPool(connection_class=GeventConnection, host='localhost', port=6379, db=0, password=None, socket_timeout=None)
        #pool = redis.ConnectionPool(connection_class=redis.UnixDomainSocketConnection, path='/var/run/redis/redis.sock', db=0)
        r = redis.Redis(connection_pool=pool)
        mypool = customDB.pool.QueuePool(customDB.getconn, max_overflow=2, pool_size=2, recycle=10)
        #_buffer = QtGui.QImage(1280, 768, QtGui.QImage.Format_RGB16)
        #_buffer = QtGui.QImage(_width, _height, QtGui.QImage.Format_RGB32)
        
        _buffer = None
        buf = None
        image = None #QtGui.QImage(buf, 64, 64, QtGui.QImage.Format_RGB32)
        buf_size = 0
        init = False
        
        #image = QtGui.QImage( 64, 64, QtGui.QImage.Format_RGB32)
        #image.fill(0)
        
        def onUpdate(destLeft, destTop, destRight, destBottom, width, height, bitsPerPixel, isCompress, data):    #buf
            """
            @summary: Bitmap transformation to Qt object
            @param width: width of bitmap
            @param height: height of bitmap
            @param bitsPerPixel: number of bit per pixel
            @param isCompress: use RLE compression
            @param data: bitmap data
            """
            #global _buffer, buf, image, buf_size, init
            
            if init == False: #setup
                if bitsPerPixel == 15:
                    buf_size = 2
                    buf = bytearray(width * height * buf_size)
                    image = QtGui.QImage(buf, width, height, QtGui.QImage.Format_RGB555)
                    _buffer = QtGui.QImage(_width, _height, QtGui.QImage.Format_RGB555)
                elif bitsPerPixel == 16:
                    buf_size = 2
                    buf = bytearray(width * height * buf_size)
                    image = QtGui.QImage(buf, width, height, QtGui.QImage.Format_RGB16)
                    _buffer = QtGui.QImage(_width, _height, QtGui.QImage.Format_RGB16)
                elif bitsPerPixel == 24:
                    buf_size = 3
                    buf = bytearray(width * height * buf_size)
                    image = QtGui.QImage(buf, width, height, QtGui.QImage.Format_RGB888)
                    _buffer = QtGui.QImage(_width, _height, QtGui.QImage.Format_RGB888)
                elif bitsPerPixel == 32:
                    buf_size = 4
                    buf = bytearray(width * height * buf_size)
                    image = QtGui.QImage(buf, width, height, QtGui.QImage.Format_RGB32)
                    _buffer = QtGui.QImage(_width, _height, QtGui.QImage.Format_RGB32)
                else:
                    buf_size = 4
                    _buffer = QtGui.QImage(_width, _height, QtGui.QImage.Format_RGB32)
                    image = QtGui.QImage(width, height, QtGui.QImage.Format_RGB32)
                init = True
                
            if isCompress:
                rle.bitmap_decompress(buf, width, height, data, buf_size)
            else:
                image = QtGui.QImage(data, width, height, QtGui.QImage.Format_RGB32).transformed(QtGui.QMatrix(1.0, 0.0, 0.0, -1.0, 0.0, 0.0))

            with QtGui.QPainter(_buffer) as qp:
                   qp.drawImage(destLeft, destTop, image, 0, 0, destRight - destLeft + 1, destBottom - destTop + 1)
    
            
        def delay_shot(SESSION_ID, ouputDirectory, Return_Msg):
            tmp = ouputDirectory+'/'+str(time.time())+"_delay_shot.jpg"
            data = {'type':'PrtScn', 'Sub_type':'delay_shot', 'data':(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()), 'TLG_ACT_IN_LOG', 'PHOTO', 33,'delay_shot', Return_Msg, tmp)}
            #r.lpush(SESSION_ID, 'FFAFF'+cjson.encode(data))
            r.lpush(SESSION_ID, 'FFAFF'+json.dumps(data))
        
        def shot(SESSION_ID, ouputDirectory, Return_Msg):
            tmp = ouputDirectory+'/'+str(time.time())+"_interval.jpg"
            data = {'type':'PrtScn', 'Sub_type':'interval', 'data':(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()), 'TLG_ACT_IN_LOG', 'PHOTO', 34,'interval', Return_Msg, tmp)}
            #r.lpush(SESSION_ID, 'FFAFF'+cjson.encode(data)) 
            r.lpush(SESSION_ID, 'FFAFF'+json.dumps(data))     
        
        init_time = time.time()
        delay_shot_time = [False, 0]

        while True:
            name, orgdata =  r.brpop(name_space)
            
            if orgdata[0:5] == 'FFAFF':
                #data = cjson.decode(orgdata[5:])
                data = json.loads(orgdata[5:])
                type = data['type']
                Sub_type = data['Sub_type']
                contents = data['data']

                if type == 'PrtScn':
                    _buffer.save(contents[-1], 'jpg', 50)
                    if Sub_type in ['click', 'keybord_enter']:
                        delay_shot_time = [True, time.time()+2]
                    try:
                        customDB.mysql_RDP_Log_Isert(mypool, contents)
                    except Exception, e:
                        print '[RDP]',e, contents
                    
                elif type == 'TEXT':
                    try:
                        customDB.mysql_RDP_Log_Isert(mypool, contents)
                    except Exception, e:
                        print '[RDP]',e, contents
                        
                elif type == 'close':
                    try:
                        customDB.make_video(mypool, contents['ouputDirectory'], contents['ouputDirectory']+"/"+name_space+'.avi', name_space)
                    except Exception, e:
                        print '[RDP make_video]',e, contents    
                                    
                    r.delete(name_space)
                    break
                else:
                    pass
                
            else:
                if delay_shot_time[0] == True and time.time() > delay_shot_time[1]:
                    delay_shot(name_space, Return_Msg['ouputDirectory'], Return_Msg)
                    delay_shot_time = [False, 0]
                else:
                    if time.time() - init_time > sleep_time:
                        init_time = time.time()
                        shot(name_space, Return_Msg['ouputDirectory'], Return_Msg)                
                #try:
                destLeft, destTop, destRight, destBottom, width, height, bitsPerPixel, isCompress, data = orgdata[1:-1].split(',')
                #onUpdate(int(destLeft), int(destTop), int(destRight), int(destBottom), int(width), int(height), int(bitsPerPixel), int(isCompress), data.strip()[1:-1].decode('hex'))
                 
                #print destLeft, destTop, destRight, destBottom, width, height, bitsPerPixel, isCompress
                if init == False: #setup
                    if int(bitsPerPixel) == 15:
                        buf_size = 2
                        buf = bytearray(int(width) * int(height) * buf_size)
                        image = QtGui.QImage(buf, int(width), int(height), QtGui.QImage.Format_RGB555)
                        _buffer = QtGui.QImage(_width, _height, QtGui.QImage.Format_RGB555)
                    elif int(bitsPerPixel) == 16:
                        buf_size = 2
                        buf = bytearray(int(width) * int(height) * buf_size)
                        image = QtGui.QImage(buf, int(width), int(height), QtGui.QImage.Format_RGB16)
                        _buffer = QtGui.QImage(_width, _height, QtGui.QImage.Format_RGB16)
                    elif int(bitsPerPixel) == 24:
                        buf_size = 3
                        buf = bytearray(int(width) * int(height) * buf_size)
                        image = QtGui.QImage(buf, int(width), int(height), QtGui.QImage.Format_RGB888)
                        _buffer = QtGui.QImage(_width, _height, QtGui.QImage.Format_RGB888)
                    elif int(bitsPerPixel) == 32:
                        buf_size = 4
                        buf = bytearray(int(width) * int(height) * buf_size)
                        image = QtGui.QImage(buf, int(width), int(height), QtGui.QImage.Format_RGB32)
                        _buffer = QtGui.QImage(_width, _height, QtGui.QImage.Format_RGB32)
                    else:
                        buf_size = 4
                        _buffer = QtGui.QImage(_width, _height, QtGui.QImage.Format_RGB32)
                        image = QtGui.QImage(int(width), int(height), QtGui.QImage.Format_RGB32)
                    init = True
                    
                if isCompress:
                    rle.bitmap_decompress(buf, int(width), int(height), data.strip()[1:-1].decode('hex'), buf_size)
                else:
                    image = QtGui.QImage(data.strip()[1:-1].decode('hex'), width, height, QtGui.QImage.Format_RGB32).transformed(QtGui.QMatrix(1.0, 0.0, 0.0, -1.0, 0.0, 0.0))
    
                with QtGui.QPainter(_buffer) as qp:
                       qp.drawImage(int(destLeft), int(destTop), image, 0, 0, int(destRight) - int(destLeft) + 1, int(destBottom) - int(destTop) + 1)
                   

        print "END"
        
    except Exception, e:
        #print e
        print "handle, Error on line (%s): %s " % (sys.exc_info()[-1].tb_lineno , str(e))

def gen_ssh_log(name_space):
    
    #pool = redis.ConnectionPool(unix_socket_path='/var/run/redis/redis.sock')
    pool = redis.ConnectionPool(connection_class=GeventConnection, host='localhost', port=6379, db=1, password=None, socket_timeout=None)
    r = redis.Redis(connection_pool=pool)
    mypool = customDB.pool.QueuePool(customDB.getconn, max_overflow=2, pool_size=1, recycle=10)
    
    while True:
        name, orgdata =  r.brpop(name_space)
        
        if orgdata[0:5] == 'FFAFF':
            #data = cjson.decode(orgdata[5:])
            data = json.loads(orgdata[5:])
            type = data['type']
            Sub_type = data['Sub_type']
            contents = data['data']
            #print time.time(), type, Sub_type
            if type == 'init':
                pass
            elif type == 'mysql_log_insert':
                try:
                    customDB.mysql_log_insert(mypool, tuple(contents), name_space)
                except Exception, e:
                    print '[SSH]',e, contents
                    
            elif type == 'mysql_insert_bin_B':
                try:
                    customDB.mysql_insert_bin_B(tuple(contents))
                except Exception, e:
                    print '[SSH]',e, contents
                    
            elif type == 'close':
                r.delete(name_space)
                break

def vnc_gen_screen_shot(name_space, save_path, Return_Msg):    
    try:
        pool = redis.ConnectionPool(connection_class=GeventConnection, host='localhost', port=6379, db=2, password=None, socket_timeout=None)
        r = redis.Redis(connection_pool=pool)
        mypool = customDB.pool.QueuePool(customDB.getconn, max_overflow=2, pool_size=2, recycle=10)
        
        data_type = ''
        
        
        contents = (time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()), 'LogIn', 'BIN', 101,Return_Msg['SESSION_ID'],Return_Msg, None)
        customDB.mysql_RDP_Log_Isert(mypool, contents)
        
        while True:
            name, orgdata =  r.brpop(name_space)
            if orgdata == 'close':
                
                contents = (time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()), 'LogOut', 'BIN', 102,Return_Msg['SESSION_ID'],Return_Msg, None)
                customDB.mysql_RDP_Log_Isert(mypool, contents)
                
                try:
                    customDB.make_video(mypool, save_path+'/'+name_space, save_path+'/'+name_space+"/"+name_space+'.avi', name_space)
                except Exception, e:
                    print '[VNC make_video]',e, contents    
                
                break

            else:
                tmp = path+'/'+name_space+'/'+orgdata
                data = orgdata.split('_')                
                if data[1][0] == '3': #INTERVAL
                    data_type = (34, 'interval')
                elif orgdata.split('_')[1][0] == '4': #key
                    data_type = (31, 'keybord_enter')
                elif orgdata.split('_')[1][0] == '5': #mouse
                    data_type = (30, 'mouse_click')
                else:
                    pass
                
                try:
                    contents = (time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()), 'TLG_ACT_IN_LOG', 'PHOTO', data_type[0],data_type[1], Return_Msg, tmp)
                    customDB.mysql_RDP_Log_Isert(mypool, contents)
                except Exception, e:
                    print '[VNC]',e, contents
                                
    except Exception, e:
        print '[VNC]', e 
                
                





                
        

def ch():
    r = redis.StrictRedis(host='localhost', port=6379, db=0)
    while True:
        time.sleep(5)    
        for a in proc_list.keys():
            if proc_list[a][0].is_alive() == False:
                if r.exists(a) == False:
                    del proc_list[a]
                    print "OK exit"
                else:
                    print "restart"
                    if len(proc_list[a][1]) > 1:
                        SESSION_ID, _width, _height, Return_Msg, sleeptime = proc_list[a][1]
                        rdp_logging =  Process(target=gen_screen_shot, args=(SESSION_ID, _width, _height, Return_Msg, sleeptime) )
                        rdp_logging.start()
                        proc_list[SESSION_ID] = [rdp_logging, proc_list[a][1]]               
                    else:
                        SESSION_ID = proc_list[a][1]
                        ssh_logging =  Process(target=gen_screen_shot, args=(SESSION_ID, ) )
                        ssh_logging.start()
                        proc_list[SESSION_ID] = [ssh_logging, proc_list[a][1]]          
                                         
if __name__ == '__main__':


    th = threading.Thread(target=ch)
    th.setDaemon(True)
    th.start()
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP
    sock.bind(('127.0.0.1', 12345))
    while True:
        data, addr = sock.recvfrom(2048)
        #print data
        method, tmp_data = json.loads(data)
        if method == 'RDP':
            SESSION_ID, _width, _height, Return_Msg, sleeptime = tmp_data
            rdp_logging =  Process(target=gen_screen_shot, args=(SESSION_ID, _width, _height, Return_Msg, sleeptime) )
            rdp_logging.start()
            proc_list[SESSION_ID] = [rdp_logging, tmp_data]   
            
        elif method == 'SSH':
            SESSION_ID = tmp_data
            ssh_logging =  Process(target=gen_ssh_log, args=(SESSION_ID, ) )
            ssh_logging.start()
            proc_list[SESSION_ID] = [ssh_logging, tmp_data]
            #r.lpush(SESSION_ID, 'FFAFF'+cjson.encode({'type':'mysql_log_insert', 'Sub_type':'','data':}))
        elif method == 'VNC':
            '''
            LISTEN_PORT
            Dest_server_ip 
            save_path
            SCREEN_INTERVAL
            SESSION_ID
            = tmp_data
            
            Return_Msg['EQP_UID']
            Return_Msg['NAME']
            Return_Msg['IP']
            Return_Msg['PK']
            Return_Msg['SESSION_ID']
            Return_Msg['tmp_auth']
            '''
            pass
          
            

