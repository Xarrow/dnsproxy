#!/usr/bin/env python
# coding:utf-8

import sys
import os
import glob

sys.path += glob.glob('%s/*.egg'%os.path.dirname(os.path.abspath(__file__)))

DummyGeventObject = type('DummyGeventObject', (object,), {'__init__':lambda *a,**kw:sys.stdout.write('*** WARNING: Please install python-gevent 1.0 ***\n\n')})
try:
    import gevent
    import gevent.core
    import gevent.queue
    import gevent.monkey
    import gevent.coros
    import gevent.server
    import gevent.pool
    import gevent.event
    import gevent.timeout
    gevent.monkey.patch_all(dns=gevent.version_info[0]>=1)
except ImportError:
    import platform
    sys.stderr.write('WARNING: python-gevent not installed. Please ')
    if sys.platform.startswith('linux'):
        sys.stderr.write('`wget --no-check-certificate --header="Host: goagent.googlecode.com" http://www.google.cn/files/gevent-1.0dev-linux-x86.egg`\n')
    elif sys.platform == 'darwin' and platform.processor() == 'i386':
        sys.stderr.write('`wget --no-check-certificate --header="Host: goagent.googlecode.com" http://www.google.cn/files/gevent-1.0dev-macosx-intel.egg`\n')
    elif os.name == 'nt':
        sys.stderr.write('visit `https://github.com/SiteSupport/gevent/downloads`\n')
    else:
        sys.stderr.write('`sudo easy_install gevent`\n')
    import threading
    Queue = __import__('queue') if sys.version[0] == '3' else __import__('Queue')
    SocketServer = __import__('socketserver') if sys.version[0] == '3' else __import__('SocketServer')

    def GeventImport(name):
        import sys
        sys.modules[name] = type(sys)(name)
        return sys.modules[name]
    def GeventSpawn(target, *args, **kwargs):
        return threading._start_new_thread(target, args, kwargs)
    def GeventSpawnLater(seconds, target, *args, **kwargs):
        def wrap(*args, **kwargs):
            import time
            time.sleep(seconds)
            return target(*args, **kwargs)
        return threading._start_new_thread(wrap, args, kwargs)
    class GeventServerStreamServer(SocketServer.ThreadingTCPServer):
        allow_reuse_address = True
        def finish_request(self, request, client_address):
            self.RequestHandlerClass(request, client_address)
    class GeventServerDatagramServer(SocketServer.ThreadingUDPServer):
        allow_reuse_address = True
        def __init__(self, server_address, *args, **kwargs):
            SocketServer.ThreadingUDPServer.__init__(self, server_address, self.__class__.RequestHandlerClass, *args, **kwargs)
            self._writelock = threading.Semaphore()
        def sendto(self, *args):
            self._writelock.acquire()
            try:
                self.socket.sendto(*args)
            finally:
                self._writelock.release()
        @staticmethod
        def RequestHandlerClass(request, client_addr, server):
            data, server_socket = request
            return server.handle(data, client_addr)
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
            return threading._start_new_thread(self.__target_wrapper, (target, args, kwargs))

    gevent        = GeventImport('gevent')
    gevent.queue  = GeventImport('gevent.queue')
    gevent.coros  = GeventImport('gevent.coros')
    gevent.server = GeventImport('gevent.server')
    gevent.pool   = GeventImport('gevent.pool')
    gevent.sleep  = __import__('time').sleep

    gevent.queue.Queue           = Queue.Queue
    gevent.queue.PriorityQueue   = Queue.PriorityQueue
    gevent.queue.Empty           = Queue.Empty
    gevent.coros.Semaphore       = threading.Semaphore
    gevent.getcurrent            = threading.currentThread
    gevent.spawn                 = GeventSpawn
    gevent.spawn_later           = GeventSpawnLater
    gevent.server.StreamServer   = GeventServerStreamServer
    gevent.server.DatagramServer = GeventServerDatagramServer
    gevent.pool.Pool             = GeventPoolPool

    gevent.version_info = (1, 0, 0, 'fake')

    del GeventImport, GeventSpawn, GeventSpawnLater,\
        GeventServerStreamServer, GeventServerDatagramServer, GeventPoolPool

import re
import time
import socket
import struct
import random
try:
    import ctypes
except ImportError:
    ctypes = None

class Logging(type(sys)):
    CRITICAL = 50
    FATAL = CRITICAL
    ERROR = 40
    WARNING = 30
    WARN = WARNING
    INFO = 20
    DEBUG = 10
    NOTSET = 0
    def __init__(self, *args, **kwargs):
        self.level = self.__class__.INFO
        if self.level > self.__class__.DEBUG:
            self.debug = self.dummy
        self.__write = __write = sys.stderr.write
        self.isatty = getattr(sys.stderr, 'isatty', lambda:False)()
        self.__set_error_color = lambda:None
        self.__set_warning_color = lambda:None
        self.__reset_color = lambda:None
        if self.isatty:
            if os.name == 'nt':
                SetConsoleTextAttribute = ctypes.windll.kernel32.SetConsoleTextAttribute
                GetStdHandle = ctypes.windll.kernel32.GetStdHandle
                self.__set_error_color = lambda:SetConsoleTextAttribute(GetStdHandle(-11), 0x04)
                self.__set_warning_color = lambda:SetConsoleTextAttribute(GetStdHandle(-11), 0x06)
                self.__reset_color = lambda:SetConsoleTextAttribute(GetStdHandle(-11), 0x07)
            elif os.name == 'posix':
                self.__set_error_color = lambda:__write('\033[31m')
                self.__set_warning_color = lambda:__write('\033[33m')
                self.__reset_color = lambda:__write('\033[0m')
    @classmethod
    def getLogger(cls, *args, **kwargs):
        return cls(*args, **kwargs)
    def basicConfig(self, *args, **kwargs):
        self.level = kwargs.get('level', self.__class__.INFO)
        if self.level > self.__class__.DEBUG:
            self.debug = self.dummy
    def log(self, level, fmt, *args, **kwargs):
        self.__write('%s - - [%s] %s\n' % (level, time.ctime()[4:-5], fmt%args))
    def dummy(self, *args, **kwargs):
        pass
    def debug(self, fmt, *args, **kwargs):
        self.log('DEBUG', fmt, *args, **kwargs)
    def info(self, fmt, *args, **kwargs):
        self.log('INFO', fmt, *args)
    def warning(self, fmt, *args, **kwargs):
        self.__set_warning_color()
        self.log('WARNING', fmt, *args, **kwargs)
        self.__reset_color()
    def warn(self, fmt, *args, **kwargs):
        self.warning(fmt, *args, **kwargs)
    def error(self, fmt, *args, **kwargs):
        self.__set_error_color()
        self.log('ERROR', fmt, *args, **kwargs)
        self.__reset_color()
    def exception(self, fmt, *args, **kwargs):
        self.error(fmt, *args, **kwargs)
        traceback.print_exc(file=sys.stderr)
    def critical(self, fmt, *args, **kwargs):
        self.__set_error_color()
        self.log('CRITICAL', fmt, *args, **kwargs)
        self.__reset_color()
logging = sys.modules['logging'] = Logging('logging')

class DNSUtil(object):
    """
    http://gfwrev.blogspot.com/2009/11/gfwdns.html
    http://zh.wikipedia.org/wiki/域名服务器缓存污染
    http://support.microsoft.com/kb/241352
    """
    blacklist = set([
                    '1.1.1.1', '255.255.255.255', # for ipv6
                    '74.125.127.102', '74.125.155.102', '74.125.39.113', '209.85.229.138', # for google+
                    '128.121.126.139', '159.106.121.75', '169.132.13.103', '192.67.198.6',
                    '202.106.1.2', '202.181.7.85', '203.161.230.171', '203.98.7.65',
                    '207.12.88.98', '208.56.31.43', '209.145.54.50', '209.220.30.174',
                    '209.36.73.33', '211.94.66.147', '213.169.251.35', '216.221.188.182',
                    '216.234.179.13', '243.185.187.39', '37.61.54.158', '4.36.66.178',
                    '46.82.174.68', '59.24.3.173', '64.33.88.161', '64.33.99.47',
                    '64.66.163.251', '65.104.202.252', '65.160.219.113', '66.45.252.237',
                    '72.14.205.104', '72.14.205.99', '78.16.49.15', '8.7.198.45', '93.46.8.89',
                    ])
    max_retry = 1
    max_wait = 3

    @staticmethod
    def _reply_to_iplist(data):
        assert isinstance(data, basestring)
        iplist = ['.'.join(str(ord(x)) for x in s) for s in re.findall('\xc0.\x00\x01\x00\x01.{6}(.{4})', data) if all(ord(x)<=255 for x in s)]
        return iplist

    @staticmethod
    def is_bad_reply(data):
        assert isinstance(data, basestring)
        iplist = ['.'.join(str(ord(x)) for x in s) for s in re.findall('\xc0.\x00\x01\x00\x01.{6}(.{4})', data) if all(ord(x)<=255 for x in s)]
        iplist += ['.'.join(str(ord(x)) for x in s) for s in re.findall('\x00\x01\x00\x01.{6}(.{4})', data) if all(ord(x)<=255 for x in s)]
        return any(x in DNSUtil.blacklist for x in iplist)

    @staticmethod
    def _remote_resolve(dnsserver, qname, timeout=None):
        if isinstance(dnsserver, tuple):
            dnsserver, port = dnsserver
        else:
            port = 53
        for i in xrange(DNSUtil.max_retry):
            host = ''.join(chr(len(x))+x for x in qname.split('.'))
            seqid = os.urandom(2)
            data = '%s\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00%s\x00\x00\x01\x00\x01' % (seqid, host)
            address_family = socket.AF_INET6 if ':' in dnsserver else socket.AF_INET
            sock = None
            try:
                if i < DNSUtil.max_retry-1:
                    # UDP mode query
                    sock = socket.socket(family=address_family, type=socket.SOCK_DGRAM)
                    sock.settimeout(timeout)
                    sock.sendto(data, (dnsserver, port))
                    for i in xrange(DNSUtil.max_wait):
                        data = sock.recv(512)
                        if data and not DNSUtil.is_bad_reply(data):
                            return data[2:]
                        else:
                            logging.warning('DNSUtil._remote_resolve(dnsserver=%r, %r) return position udp data=%r', qname, dnsserver, data)
                else:
                    # TCP mode query
                    sock = socket.socket(family=address_family, type=socket.SOCK_STREAM)
                    sock.settimeout(timeout)
                    sock.connect((dnsserver, port))
                    data = struct.pack('>h', len(data)) + data
                    sock.send(data)
                    rfile = sock.makefile('r', 512)
                    data = rfile.read(2)
                    if not data:
                        logging.warning('DNSUtil._remote_resolve(dnsserver=%r, %r) return bad tcp header data=%r', qname, dnsserver, data)
                    data = rfile.read(struct.unpack('>h', data)[0])
                    if data and not DNSUtil.is_bad_reply(data):
                        return data[2:]
                    else:
                        logging.warning('DNSUtil._remote_resolve(dnsserver=%r, %r) return bad tcp data=%r', qname, dnsserver, data)
            except socket.error as e:
                if e[0] in (10060, 'timed out'):
                    continue
            except Exception as e:
                raise
            finally:
                if sock:
                    sock.close()

    @staticmethod
    def remote_resolve(dnsserver, qname, timeout=None):
        data = DNSUtil._remote_resolve(dnsserver, qname, timeout)
        iplist = DNSUtil._reply_to_iplist(data or '')
        return iplist


class DNSServer(getattr(gevent.server, 'DatagramServer', DummyGeventObject)):
    """DNS Proxy over TCP to avoid DNS poisoning"""
    dnsservers = ['8.8.8.8', '8.8.4.4']
    max_wait = 1
    max_retry = 2
    max_cache_size = 2000
    timeout   = 6

    def __init__(self, *args, **kwargs):
        gevent.server.DatagramServer.__init__(self, *args, **kwargs)
        self.cache = {}
    def handle(self, data, address):
        reqid   = data[:2]
        domain  = data[12:data.find('\x00', 12)]
        if len(self.cache) > self.max_cache_size:
            self.cache.clear()
        if domain not in self.cache:
            qname = re.sub(r'[\x01-\x29]', '.', domain[1:])
            try:
                dnsserver = random.choice(self.dnsservers)
                logging.info('DNSServer resolve domain=%r by dnsserver=%r to iplist', qname, dnsserver)
                data = DNSUtil._remote_resolve(dnsserver, qname, self.timeout)
                if not data:
                    logging.warning('DNSServer resolve domain=%r return data=%s', qname, data)
                    return
                iplist = DNSUtil._reply_to_iplist(data)
                self.cache[domain] = data
                logging.info('DNSServer resolve domain=%r return iplist=%s', qname, iplist)
            except socket.error as e:
                logging.error('DNSServer resolve domain=%r to iplist failed:%s', qname, e)
        return self.sendto(reqid + self.cache[domain], address)


def main():
    logging.basicConfig(level=logging.DEBUG, format='%(levelname)s - %(asctime)s %(message)s', datefmt='[%b %d %H:%M:%S]')
    address = ('', 53)
    server = DNSServer(address)
    logging.info('serving at %r', address)
    server.serve_forever()

if __name__ == '__main__':
    main()
