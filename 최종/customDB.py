# -*- coding: utf-8 -*-
import MySQLdb
import sqlalchemy.pool as pool
import pybase64
import StringIO
#import pyte
#from pyte import modes as mo
import time, cjson
import re
from io import BytesIO
from PIL import Image
import os, glob
import socket
import sys


dbname = 'KTWIZSTICK'
dbuser = 'ktwiz'
dbpasswd = 'wheotjdroqkftjqj1!'
dbhost = '220.118.10.103'
dbport = 3306
reaesc = re.compile(r'\x1b[^m]*m')

def mysql_conn(sql_tmp):
    db = MySQLdb.connect(db=dbname,user=dbuser, passwd=dbpasswd, host=dbhost, port = dbport)
    cur = db.cursor()
    cur.execute(sql_tmp)
    result =cur.fetchall()
    cur.close()
    db.close()
    return result

def getconn():
    mysql = MySQLdb.connect(db=dbname,user=dbuser, passwd=dbpasswd, host=dbhost, port = dbport, charset='utf8')
    return mysql

def mysql_insert(sql_tmp):
    conn = mypool.connect()
    cur = conn.cursor()
    cur.execute(sql_tmp)
    cur.close()
    conn.close()
    return

def mysql_except_log_insert(sql_tmp):
    
    #socket.gethostname() 
    #socket.gethostbyaddr(socket.gethostname())[0]
    #print sql_tmp
    db = MySQLdb.connect(db=dbname,user=dbuser, passwd=dbpasswd, host=dbhost, port = dbport)
    cur = db.cursor()
    cur = conn.cursor()
    cur.execute("Insert into KTWIZSTICK.TLG_SYS_LOG (LOG_DTM, LOG_TYPE, LOG_TEXT, LOG_IP) VALUES (%s, %s, %s, %s)", sql_tmp)
    cur.commit()
    cur.close()
    db.close()
    return

'''
def mysql_insert_bin_B(sql_tmp, path_tmp):
    with open(path_tmp,'r') as f:
        data = f.read()        
    sql_tmp = sql_tmp + (pybase64.standard_b64encode(data), )
    conn = MySQLdb.connect(db=dbname,user=dbuser, passwd=dbpasswd, host=dbhost, port = dbport)
    cur = conn.cursor()
    cur.execute("""INSERT INTO KTWIZSTICK.TLG_ACT_OUT_LOG (LOG_DTM, LOG_START, LOG_END, EQP_UID, EQP_NAME, EQP_IP, SERIAL, USER_NAME, LOGIN_ID, LOG_TEXT) VALUES (CURRENT_TIMESTAMP(), %s, %s, %s, %s, %s, %s, %s, %s, %s );commit;""" , sql_tmp)
    cur.close()
    conn.close()
'''
def bufcount(filename):
    f = open(filename)                  
    lines = 0
    buf_size = 1024 * 1024
    read_f = f.read # loop optimization

    buf = read_f(buf_size)
    while buf:
        lines += buf.count('\n')
        buf = read_f(buf_size)
    return lines
    
def mysql_insert_bin_B(sql_tmp, path_tmp):
    #ss = time.time()
    #print "START !!"
    new_text = reaesc.sub('', open(path_tmp, 'rb').read().replace('\x1b[K\r\n', '\n'))
    '''
    output = StringIO.StringIO()
    screen = pyte.HistoryScreen(120, 24,ratio=1)
    screen.set_mode(mo.LNM)
    stream = pyte.ByteStream(screen)
    for data in open(path_tmp, 'rb').readlines():
        stream.feed(data)
        for a in screen.display:
            if a == u'                                                                                                                        ':
                pass
            else:
                #print [a]
                output.write(a+'\n')
        screen.reset()       
     '''

    '''
    output = StringIO.StringIO()
    output2 = StringIO.StringIO()
    stream = pyte.ByteStream(pyte.DebugScreen(to=output))
    stream.feed(open(path_tmp, 'rb').read())
    output.seek(0)
    for line in output:
        #["draw", ["DIRMASK = (1 << DIRBITS) - 1"], {}]
        a = cjson.decode(line)
        if a[0] == 'draw':
            #print a[1][0]
            output2.write(a[1][0]+'\n')
            
    output.close()
    '''
    #print 'END',  time.time() -ss
    '''
    count =  bufcount(path_tmp)
    screen = pyte.HistoryScreen(80, count,  ratio=1)
    stream = pyte.Stream(screen)
    stream.feed(open(path_tmp, 'rb').read())
    
    for a in  screen.display:
        if a == u'                                                                                ':
            pass
        else:
            output.write(a+'\n')
    '''
    #print str(output.getvalue())
    #str(output.getvalue())
    sql_tmp = sql_tmp + (pybase64.standard_b64encode(new_text), )
    #output.close()
    #output2.close()
    
    conn = MySQLdb.connect(db=dbname,user=dbuser, passwd=dbpasswd, host=dbhost, port = dbport)
    cur = conn.cursor()
    cur.execute("""INSERT INTO KTWIZSTICK.TLG_ACT_OUT_LOG (LOG_DTM, LOG_START, LOG_END, EQP_UID, EQP_NAME, EQP_IP, SERIAL, USER_NAME, LOGIN_ID, LOG_DATA_TYPE, SESSION_ID, LOG_TEXT, PROTOCOL) VALUES (CURRENT_TIMESTAMP(), %s, %s, %s, %s, %s, %s, %s, %s, %s, %s , %s,  'SSH');""" , sql_tmp)
    cur.close()
    conn.commit()
    conn.close()
    
    
     
def mysql_insert_bin(mypool, sql_tmp, path_tmp):
    with open(path_tmp,'r') as f:
        data = f.read()        
    sql_tmp = sql_tmp + (pybase64.standard_b64encode(data), )
    conn = mypool.connect()
    cur = conn.cursor()
    cur.execute("""INSERT INTO KTWIZSTICK.TLG_ACT_OUT_LOG (LOG_DTM, LOG_START, LOG_END, EQP_UID, EQP_NAME, EQP_IP, SERIAL, USER_NAME, LOGIN_ID, LOG_TEXT) VALUES (CURRENT_TIMESTAMP(), %s, %s, %s, %s, %s, %s, %s, %s, %s );commit;""" , sql_tmp)
    cur.close()
    conn.close()
    
def mysql_log_insert(mypool, sql_tmp, SESSION_ID = None):
    conn = mypool.connect()
    cur = conn.cursor()
   
    if sql_tmp[9] == 'LogIn' :
        if sql_tmp[11] == True:
            tmp_auth = 1
        else:
            tmp_auth = 0
            
        cur.execute('''INSERT INTO KTWIZSTICK.TST_ACT_STS (SESSION_ID, EQP_UID, SERIAL, LOGIN_DTM, TMP_AUTH) VALUES (%s, %s, %s, %s, %s);''',(SESSION_ID, sql_tmp[1], sql_tmp[4], sql_tmp[0], tmp_auth))
        sql_tmp = sql_tmp[:-1] +(SESSION_ID, )
        cur.execute("""INSERT INTO KTWIZSTICK.TLG_ACT_IN_LOG (LOG_DTM, EQP_UID, EQP_NAME, EQP_IP, SERIAL, USER_NAME, LOGIN_ID, LOG_TYPE, ACTION_TYPE, LOG_TEXT, LOG_DATA_TYPE, SESSION_ID, PROTOCOL) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'SSH');""",sql_tmp)
    elif sql_tmp[9] == 'LogOut':
        #print sql_tmp[9]
        sql_tmp = sql_tmp + (SESSION_ID, )
        cur.execute('''UPDATE KTWIZSTICK.TST_ACT_STS SET LOGOUT_DTM = %s WHERE SESSION_ID = %s;''',(sql_tmp[0], SESSION_ID))
        cur.execute("""INSERT INTO KTWIZSTICK.TLG_ACT_IN_LOG (LOG_DTM, EQP_UID, EQP_NAME, EQP_IP, SERIAL, USER_NAME, LOGIN_ID, LOG_TYPE, ACTION_TYPE, LOG_TEXT, LOG_DATA_TYPE, SESSION_ID, PROTOCOL) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'SSH');""",sql_tmp)
    else:
        sql_tmp = sql_tmp + (SESSION_ID, )
        cur.execute("""INSERT INTO KTWIZSTICK.TLG_ACT_IN_LOG (LOG_DTM, EQP_UID, EQP_NAME, EQP_IP, SERIAL, USER_NAME, LOGIN_ID, LOG_TYPE, ACTION_TYPE, LOG_TEXT, LOG_DATA_TYPE, SESSION_ID, PROTOCOL) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'SSH');""",sql_tmp)
    #cur.execute("commit")
    
    cur.close()
    conn.commit()
    conn.close()
    return

def mysql_User_insert(mypool, sql_tmp):
    conn = mypool.connect()
    cur = conn.cursor(MySQLdb.cursors.DictCursor)
    Return_Msg = ('False','')
    cur.execute("""SELECT *  FROM KTWIZSTICK.TAA_USER where SERIAL =%s;""", (sql_tmp[0],))
    result = cur.fetchone()
    
    if result == None:
        cur.execute("""SELECT count(SERIAL)  FROM KTWIZSTICK.TAA_USER where USER_ID =%s;""", (sql_tmp[6],))
        result = cur.fetchone()

        if result['count(SERIAL)'] == 0:
            cur.execute("""insert into KTWIZSTICK.TAA_USER (SERIAL, NAME, ORG, PHONE, EMAIL, CREATE_ID, CREATE_DTM, AUTH_DIV, USER_ID, WIZSTICK) values (%s, %s, %s, %s, %s, 'SYSTEM', %s, '10', %s, %s);commit;""",sql_tmp)
            Return_Msg = ('True', u'등록 요청을 완료하였습니다.')
        else:
            Return_Msg = ('False', u'이미 사용중인 ID 입니다.')
                
    else:
        if result['DEL_YN'] == 1: #del user
            cur.execute("""update KTWIZSTICK.TAA_USER set AUTH_DIV=10, DEL_YN = 0, NAME = %s, ORG = %s, PHONE = %s, EMAIL = %s where SERIAL = %s;commit;""", (sql_tmp[1], sql_tmp[2], sql_tmp[3], sql_tmp[4], sql_tmp[0]))
            Return_Msg = ('True', u'재등록 요청을 완료하였습니다.')
        elif result['DEL_YN'] == 0:

            if result['AUTH_DIV'] == 30:
                Return_Msg = ('False', u'이미 승인 완료된 사용자입니다.')
            elif result['AUTH_DIV'] == 10:
                Return_Msg = ('False', u'승인 대기중인 사용자입니다.')
            elif result['AUTH_DIV'] == 20:
                Return_Msg = ('False', u'승인 반려된 사용자 입니다.')
    cur.close()
    conn.close()
    return Return_Msg

def mysql_User_Authorization(mypool, sql_tmp):
    conn = mypool.connect()
    cur = conn.cursor()
    cur.execute("""SELECT EQP_STATUS, IP, L4PORT, PROTOCOL, CMD_UID, NAME, RDP_OUT_TIMER, RDP_OUT_YN, RDP_IN_YN  FROM KTWIZSTICK.TTP_EQP where EQP_UID = %s;""", (sql_tmp[0],))
    PROTOCOL = ''
    result = cur.fetchone()

    EQP_STATUS, IP, L4PORT, PROTOCOL, CMD_UID, NAME, RDP_OUT_TIMER, RDP_OUT_YN, RDP_IN_YN  = result

    if EQP_STATUS == 1:
        pass
    else:
        cur.close()
        conn.close()
        return (False, u'관라자가 장치를 비활성화 하였습니다.')
    
    cur.execute("""SELECT count(*) FROM KTWIZSTICK.TAA_EQP_USER  where EQP_UID = %s AND SERIAL = %s;""", sql_tmp)
    result = cur.fetchone()

    cur.close()
    conn.close()
    if result[0] == 1:
        return (True, {'IP':IP, 'L4PORT':L4PORT, 'PROTOCOL':PROTOCOL, 'CMD_UID':CMD_UID, 'NAME':NAME, 'RDP_OUT_TIMER':RDP_OUT_TIMER, 'RDP_OUT_YN':RDP_OUT_YN, 'RDP_IN_YN':RDP_IN_YN})
    else:
        return (False,u'장비의 접근 권한이 없습니다.')
    
    return (False, u'')


def mysql_EQP_List(mypool, sql_tmp):
    conn = mypool.connect()
    cur = conn.cursor(MySQLdb.cursors.DictCursor)    
    
    cur.execute("""SELECT *  FROM KTWIZSTICK.TAA_USER where SERIAL =%s;""", sql_tmp)
    result = cur.fetchone()
    if result == None:
        return ('False', u'등록되지 않은 사용자 입니다.')
    elif result['DEL_YN'] == 1:
        return ('False', u'삭제된 사용자 입니다.')
    elif result['AUTH_DIV'] != 30:
        return ('False', u'승인대기 또는 반려된 사용자 입니다.')
    
    
    #"""SELECT EQP_UID FROM KTWIZSTICK.TAA_EQP_USER where SERIAL = %s;"""
    tmp = """SELECT TTP_EQP.EQP_UID, TTP_EQP.NAME, TTP_EQP.MODEL, TTP_EQP.IP, TTP_EQP.PROTOCOL, TTP_EQP.GROUP_UID, TTP_EQP.USAGE_NOTE FROM (SELECT * FROM KTWIZSTICK.TAA_EQP_USER where SERIAL = %s) AS t1 join KTWIZSTICK.TTP_EQP on TTP_EQP.EQP_UID=t1.EQP_UID"""
    cur.execute(tmp, sql_tmp)
    result_EQP = cur.fetchall()
     
    cur.execute("""SELECT GROUP_UID, PARENT_UID, NAME FROM KTWIZSTICK.TTP_EQP_GROUP;""")
    result_group =cur.fetchall()
    
    cur.close()
    conn.close()

    
    return ('True', (result_EQP, result_group))



def resize(path):
    fd = BytesIO()
    #fd.flush()
    #w, h = img.size
    Image.open(path).resize((800, 600), Image.ANTIALIAS).save(fd, 'JPEG', quality=50)
    return fd.getvalue()

def make_video(mypool, images, outvid=None, SESSION_ID = '' ,fps=5, size=None, is_color=True, format="XVID" ):
    try:
        """
        Create a video from a list of images.
     
        @param      outvid      output video
        @param      images      list of images to use in the video
        @param      fps         frame per second
        @param      size        size of each frame
        @param      is_color    color
        @param      format      see http://www.fourcc.org/codecs.php
        @return                 see http://opencv-python-tutroals.readthedocs.org/en/latest/py_tutorials/py_gui/py_video_display/py_video_display.html
     
        The function relies on http://opencv-python-tutroals.readthedocs.org/en/latest/.
        By default, the video will have the size of the first image.
        It will resize every image to this size before adding them to the video.
        """
        #print images
        images = glob.glob(images+"/*.jpg")
        images.sort()
        
        from cv2 import VideoWriter, VideoWriter_fourcc, imread, resize
        fourcc = VideoWriter_fourcc(*format)
        vid = None
        for image in images:
            #print image
    
            if not os.path.exists(image):
                raise FileNotFoundError(image)
            img = imread(image)
            if vid is None:
                if size is None:
                    size = img.shape[1], img.shape[0]
                vid = VideoWriter(outvid, fourcc, float(fps), size, is_color)
            if size[0] != img.shape[1] and size[1] != img.shape[0]:
                img = resize(img, size)
            
            vid.write(img)
    
                
        if vid == None:
            return
        
        vid.release()
    
        
        conn = mypool.connect()
        cur = conn.cursor()
        cur.execute('''UPDATE KTWIZSTICK.TLG_ACT_OUT_LOG SET LOG_BIN = %s WHERE SESSION_ID = %s;''',(open(outvid, 'rb').read(), str(SESSION_ID)))
        cur.close()
        conn.commit()
        conn.close() 
    except Exception, e:
        print image, " Error on line (%s) : %s " % (sys.exc_info()[-1].tb_lineno, str(e))
    #return vid


def mysql_RDP_Log_Isert(mypool, data):
    log_time, tables, LOG_DATA_TYPE, LOG_TYPE, LOG_TEXT, Return_Msg, filename = data
    LOGIN_ID = Return_Msg['Hostname']
    #LOG_TYPE = 20
    ACTION_TYPE = 1
    conn = mypool.connect()
    cur = conn.cursor()
    BIN = ''
    if filename != None:
        BIN = resize(filename)
        #with open(filename,'r') as f:
        #    BIN = f.read()
            
    if tables == 'TLG_ACT_IN_LOG':
        sql_tmp = (log_time, Return_Msg['EQP_UID'], Return_Msg['NAME'],Return_Msg['IP'], Return_Msg['PK'], '', LOGIN_ID, LOG_TYPE, ACTION_TYPE, LOG_TEXT, LOG_DATA_TYPE, Return_Msg['SESSION_ID'], BIN)
        cur.execute("""INSERT INTO KTWIZSTICK.TLG_ACT_IN_LOG (LOG_DTM, EQP_UID, EQP_NAME, EQP_IP, SERIAL, USER_NAME, LOGIN_ID, LOG_TYPE, ACTION_TYPE, LOG_TEXT, LOG_DATA_TYPE, SESSION_ID, LOG_BIN, PROTOCOL) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'RDP');""",sql_tmp)
    elif tables == 'TLG_ACT_OUT_LOG':
        sql_tmp = (log_time, )
    elif tables == 'LogIn':
        if Return_Msg['tmp_auth'] == True:
            tmp_auth = 1
        else:
            tmp_auth = 0
        cur.execute('''INSERT INTO KTWIZSTICK.TST_ACT_STS (SESSION_ID, EQP_UID, SERIAL, LOGIN_DTM, TMP_AUTH) VALUES (%s, %s, %s, %s, %s);''',(Return_Msg['SESSION_ID'], Return_Msg['EQP_UID'], Return_Msg['PK'], log_time, tmp_auth))
        sql_tmp = (log_time, Return_Msg['EQP_UID'], Return_Msg['NAME'], Return_Msg['IP'], Return_Msg['PK'], '', LOGIN_ID, 101, 0,'LogIn', 'TEXT', Return_Msg['SESSION_ID'])
        cur.execute("""INSERT INTO KTWIZSTICK.TLG_ACT_IN_LOG (LOG_DTM, EQP_UID, EQP_NAME, EQP_IP, SERIAL, USER_NAME, LOGIN_ID, LOG_TYPE, ACTION_TYPE, LOG_TEXT, LOG_DATA_TYPE, SESSION_ID, PROTOCOL) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'RDP');""",sql_tmp)
        sql_tmp = (log_time, '1970-01-01 00:00:00', Return_Msg['EQP_UID'], Return_Msg['NAME'], Return_Msg['IP'], Return_Msg['PK'], '', LOGIN_ID, 'RDP', Return_Msg['SESSION_ID'], Return_Msg['SESSION_ID'])
        cur.execute("""INSERT INTO KTWIZSTICK.TLG_ACT_OUT_LOG (LOG_DTM, LOG_START, LOG_END, EQP_UID, EQP_NAME, EQP_IP, SERIAL, USER_NAME, LOGIN_ID, LOG_DATA_TYPE, SESSION_ID, LOG_TEXT, PROTOCOL) VALUES (CURRENT_TIMESTAMP(), %s, %s, %s, %s, %s, %s, %s, %s, %s, %s , %s, 'RDP' );""" , sql_tmp)
    elif tables == 'LogOut':
        cur.execute('''UPDATE KTWIZSTICK.TST_ACT_STS SET LOGOUT_DTM = %s WHERE SESSION_ID = %s;''',(log_time, Return_Msg['SESSION_ID']))
        sql_tmp = (log_time, Return_Msg['EQP_UID'], Return_Msg['NAME'], Return_Msg['IP'], Return_Msg['PK'], '', LOGIN_ID, 102, 0,'LogOut', 'TEXT', Return_Msg['SESSION_ID'])
        cur.execute("""INSERT INTO KTWIZSTICK.TLG_ACT_IN_LOG (LOG_DTM, EQP_UID, EQP_NAME, EQP_IP, SERIAL, USER_NAME, LOGIN_ID, LOG_TYPE, ACTION_TYPE, LOG_TEXT, LOG_DATA_TYPE, SESSION_ID, PROTOCOL) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'RDP' );""",sql_tmp)
        cur.execute('''UPDATE KTWIZSTICK.TLG_ACT_OUT_LOG SET LOG_END = %s WHERE SESSION_ID = %s;''',(log_time, Return_Msg['SESSION_ID']))
        
        
    cur.close()
    conn.commit()
    conn.close() 

if __name__ == "__main__":
    db = MySQLdb.connect(db=dbname,user=dbuser, passwd=dbpasswd, host=dbhost, port = dbport)
    cur = db.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("SELECT * FROM KTWIZSTICK.TAA_USER where SERIAL ='0052c48cf50dd88730a288e2b80ecc2c816aaf60b67936ccb177f4fe';")
    result =cur.fetchone()
    print len(result)
    print result
    
    cur.close()
    db.close()
    