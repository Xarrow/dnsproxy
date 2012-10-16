#!/usr/bin/env python
# coding:utf-8

import sys
import os

try:
    import gevent
    import gevent.queue
    import gevent.monkey
    import gevent.coros
    import gevent.server
    import gevent.pool
    gevent.monkey.patch_all(dns=gevent.version_info[0]>=1)
except ImportError:
    if os.name == 'nt':
        sys.stderr.write('WARNING: python-gevent not installed. `http://code.google.com/p/gevent/downloads/list`\n')
    else:
        sys.stderr.write('WARNING: python-gevent not installed. `curl -k -L http://git.io/I9B7RQ|sh`\n')
    import Queue
    import thread
    import threading
    import SocketServer

    def GeventImport(name):
        import sys
        sys.modules[name] = type(sys)(name)
        return sys.modules[name]
    def GeventSpawn(target, *args, **kwargs):
        return thread.start_new_thread(target, args, kwargs)
    def GeventSpawnLater(seconds, target, *args, **kwargs):
        def wrap(*args, **kwargs):
            import time
            time.sleep(seconds)
            return target(*args, **kwargs)
        return thread.start_new_thread(wrap, args, kwargs)
    class GeventServerStreamServer(SocketServer.ThreadingTCPServer):
        allow_reuse_address = True
        def __init__(self, server_address, *args, **kwargs):
            SocketServer.ThreadingTCPServer.__init__(self, server_address, *args, **kwargs)
            self.address = self.server_address
        def finish_request(self, request, client_address):
            self.RequestHandlerClass(request, client_address)
    class GeventServerDatagramServer(SocketServer.ThreadingUDPServer):
        allow_reuse_address = True
        def __init__(self, server_address, *args, **kwargs):
            SocketServer.ThreadingUDPServer.__init__(self, server_address, self.RequestHandlerClass, *args, **kwargs)
            self.address = self.server_address
            self._writelock = threading.Semaphore()
        def sendto(self, *args):
            self._writelock.acquire()
            try:
                self.socket.sendto(*args)
            finally:
                self._writelock.release()
        def RequestHandlerClass(self, (data, server_socket), client_addr, server):
            return self.handle(data, client_addr)
        def handle(self, data, address):
            raise NotImplemented()
    class GeventPoolPool(object):
        def __init__(self, size):
            self._lock = threading.Semaphore(size)
        def __target_wrapper(self, target, args, kwargs):
            t = threading.Thread(target=target, args=args, kwargs=kwargs)
            try:
                t.start()
                t.join()
            except Exception as e:
                logging.error('threading.Thread target=%r error:%s', target, e)
            finally:
                self._lock.release()
        def spawn(self, target, *args, **kwargs):
            self._lock.acquire()
            return thread.start_new_thread(self.__target_wrapper, (target, args, kwargs))

    gevent        = GeventImport('gevent')
    gevent.queue  = GeventImport('gevent.queue')
    gevent.coros  = GeventImport('gevent.coros')
    gevent.server = GeventImport('gevent.server')
    gevent.pool   = GeventImport('gevent.pool')

    gevent.queue.Queue           = Queue.Queue
    gevent.coros.Semaphore       = threading.Semaphore
    gevent.getcurrent            = threading.currentThread
    gevent.spawn                 = GeventSpawn
    gevent.spawn_later           = GeventSpawnLater
    gevent.server.StreamServer   = GeventServerStreamServer
    gevent.server.DatagramServer = GeventServerDatagramServer
    gevent.pool.Pool             = GeventPoolPool

    del GeventImport, GeventSpawn, GeventSpawnLater, GeventServerStreamServer, GeventServerDatagramServer, GeventPoolPool

import re
import time
import SocketServer
import threading
import logging
import socket
import struct
import collections

class DNSServer(gevent.server.DatagramServer):
    """DNS Proxy over TCP to avoid DNS poisoning"""
    upstream_address = ('8.8.8.8', 53)
    max_retry = 3
    max_cache_size = 2000
    timeout   = 3
    poolsize  = 10

    def __init__(self, *args, **kwargs):
        gevent.server.DatagramServer.__init__(self, *args, **kwargs)
        self._cache = {}
        self._dispatchinfo = collections.defaultdict(list)
        self._dispatchlet = None
        self._dispatchlet_lock = gevent.coros.Semaphore()
        self._upstream_sock = None
        self._upstream_sock_writelock = gevent.coros.Semaphore()
    def _dispath(self, sock):
        rfile = sock.makefile('rb', 8192)
        while 1:
            tcpheader = rfile.read(2)
            length = struct.unpack('!h', tcpheader)[0]
            udpdata = rfile.read(length)
            reqid = udpdata[:2]
            domain = udpdata[12:udpdata.find('\x00', 12)]
            self._cache[domain] = udpdata
            addresses = self._dispatchinfo.pop((reqid, domain), [])
            for address in addresses:
                self.sendto(reqid+udpdata[2:], address)
    def _connect(self, address):
        with self._dispatchlet_lock:
            if self._dispatchlet is not None:
                self._dispatchlet.kill()
            self._upstream_sock = socket.create_connection(address, timeout=self.timeout)
            self._dispatchlet = gevent.spawn(self._dispath, self._upstream_sock.dup())
    def handle(self, data, address):
        if self._dispatchlet is None:
            self._connect(self.upstream_address)
        reqid   = data[:2]
        domain  = data[12:data.find('\x00', 12)]
        if len(self._cache) > self.max_cache_size:
            self._cache.clear()
        try:
            self.sendto(reqid+self._cache[domain][2:], address)
        except KeyError:
            self._dispatchinfo[reqid, domain].append(address)
            qname = re.sub(r'[\x01-\x1f]', '.', domain[1:])
            logging.info('DNSServer resolve domain=%r to iplist', qname)
            with self._upstream_sock_writelock:
                self._upstream_sock.sendall(struct.pack('!h', len(data)) + data)

def main():
    logging.basicConfig(level=logging.DEBUG, format='%(levelname)s - %(asctime)s %(message)s', datefmt='[%b %d %H:%M:%S]')
    server = DNSServer(('', 53))
    logging.info('serving at %r', server.address)
    server.serve_forever()

if __name__ == '__main__':
    main()
