import socket
import sys
import signal
import gevent

import hmac
from gevent.server import StreamServer
from gevent.socket import create_connection, gethostbyname


class PortForwarder(StreamServer):

    def __init__(self, listener, dest, authkey, **kwargs):
        StreamServer.__init__(self, listener, **kwargs)
        #self.localport = StreamServer.server_port
        self.dest = dest
        self.authkey = authkey
        
    def handle(self, source, address): # pylint:disable=method-hidden
        #log('%s:%s accepted', *address[:2])
        try:
            dest = create_connection(self.dest)
        except IOError as ex:
            #log('%s:%s failed to connect to %s:%s: %s', address[0], address[1], self.dest[0], self.dest[1], ex)
            return
        
        message = dest.recv(20)
        #print '1', [message]
        digest = hmac.new(self.authkey, message).digest()
        #print '2',[digest]
        dest.send(digest)
        
        
        forwarders = (gevent.spawn(forward, source, dest, self),
                      gevent.spawn(forward, dest, source, self))
        # if we return from this method, the stream will be closed out
        # from under us, so wait for our children
        gevent.joinall(forwarders)

    def close(self):
        if self.closed:
            sys.exit('Multiple exit signals received - aborting.')
        else:
            #log('Closing listener socket')
            StreamServer.close(self)


def forward(source, dest, server):
    source_address = '%s:%s' % source.getpeername()[:2]
    dest_address = '%s:%s' % dest.getpeername()[:2]
    try:
        while True:
            try:
                data = source.recv(1024)
                #print [data]
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


def parse_address(address):
    try:
        hostname, port = address.rsplit(':', 1)
        port = int(port)
    except ValueError:
        sys.exit('Expected HOST:PORT: %r' % address)
    return gethostbyname(hostname), port


def main(source, dest, authkey):    
    server = PortForwarder(source, dest, authkey)
    #log('Starting port forwarder %s:%s -> %s:%s', *(server.address[:2] + dest))
    gevent.signal(signal.SIGTERM, server.close)
    gevent.signal(signal.SIGINT, server.close)
    server.start()
    gevent.wait()

def log(message, *args):
    return
    message = message % args
    sys.stderr.write(message + '\n')


if __name__ == '__main__':
    source = '127.0.0.1:8080'
    dest = parse_address('128.134.101.135:60000')
    
    main(source, dest, authkey)