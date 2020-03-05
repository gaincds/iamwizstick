# coding: utf-8

import sys

from twisted.internet import defer
from twisted.internet import protocol
from twisted.internet import reactor
#from twisted.python import log
import hmac

class ProxyClientProtocol(protocol.Protocol):
    AUTHKEY = ''
    
    def connectionMade(self):
        self.first_con = True
        #log.msg("Client: connected to peer")
        self.cli_queue = self.factory.cli_queue
        self.cli_queue.get().addCallback(self.serverDataReceived)
    
    def serverDataReceived(self, chunk):
        if chunk is False:
            self.cli_queue = None
            #log.msg("Client: disconnecting from peer")
            self.factory.continueTrying = False
            self.transport.loseConnection()
            reactor.stop
            
        elif self.cli_queue:
            #log.msg("Client: writing %d bytes to peer" % len(chunk))
            self.transport.write(chunk)
            self.cli_queue.get().addCallback(self.serverDataReceived)
        else:
            self.factory.cli_queue.put(chunk)

    def dataReceived(self, chunk):
        #log.msg("Client: %d bytes received from peer" % len(chunk))
        
        if self.first_con == True:
            message = chunk[0:20]
            #print self.AUTHKEY
            self.transport.write(hmac.new(self.AUTHKEY, message).digest())
            self.first_con = False
            return
            
        self.factory.srv_queue.put(chunk)

    def connectionLost(self, why):
        if self.cli_queue:
            self.cli_queue = None
            #log.msg("Client: peer disconnected unexpectedly")


class ProxyClientFactory(protocol.ReconnectingClientFactory):
    maxDelay = 10
    continueTrying = True
    protocol = ProxyClientProtocol
     
    def __init__(self, srv_queue, cli_queue):
        self.srv_queue = srv_queue
        self.cli_queue = cli_queue

        


class ProxyServer(protocol.Protocol):
    IP = ''
    PORT = 0
    AUTHKEY = ''
    
    def connectionMade(self):
        
        self.srv_queue = defer.DeferredQueue()
        self.cli_queue = defer.DeferredQueue()
        self.srv_queue.get().addCallback(self.clientDataReceived)

        factory = ProxyClientFactory(self.srv_queue, self.cli_queue)
        factory.protocol.AUTHKEY = self.AUTHKEY
        
        reactor.connectTCP(self.IP, self.PORT, factory)

    def clientDataReceived(self, chunk):
        #log.msg("Server: writing %d bytes to original client" % len(chunk))
        self.transport.write(chunk)
        self.srv_queue.get().addCallback(self.clientDataReceived)

    def dataReceived(self, chunk):
        #log.msg("Server: %d bytes received" % len(chunk))
        self.cli_queue.put(chunk)

    def connectionLost(self, why):
        self.cli_queue.put(False)

def main(lo_addr, R_addr, AUTHKEY):
    #print lo_addr, R_addr, [AUTHKEY]
    
    #log.startLogging(sys.stdout)
    factory = protocol.Factory()
    factory.protocol = ProxyServer
    factory.protocol.IP = R_addr[0]
    factory.protocol.PORT = R_addr[1]
    factory.protocol.AUTHKEY = AUTHKEY
    
    
    reactor.listenTCP(int(lo_addr), factory, interface="127.0.0.1")
    reactor.run()    

if __name__ == "__main__":
    log.startLogging(sys.stdout)
    factory = protocol.Factory()
    factory.protocol = ProxyServer
    factory.protocol.IP = "128.134.101.135"
    factory.protocol.PORT = 46012
    factory.protocol.AUTHKEY = '656678'
    reactor.listenTCP(9996, factory, interface="0.0.0.0")
    reactor.run()