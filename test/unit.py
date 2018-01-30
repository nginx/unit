import os
import re
import sys
import json
import time
import shutil
import socket
import tempfile
import unittest
from requests import Request, Session
from subprocess import call
from multiprocessing import Process

class TestUnit(unittest.TestCase):

    pardir = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))

    def setUp(self):
        self._run()

    def tearDown(self):
        self._stop()

        if '--log' in sys.argv:
            with open(self.testdir + '/unit.log', 'r') as f:
                print(f.read())

        if '--leave' not in sys.argv:
            shutil.rmtree(self.testdir)

    def check_modules(self, *modules):
        self._run()

        for i in range(50):
            with open(self.testdir + '/unit.log', 'r') as f:
                log = f.read()
                m = re.search('controller started', log, re.M | re.S)

                if m is None:
                    time.sleep(0.1)
                else:
                    break

        if m is None:
            exit("Unit is writing log too long")

        missed_module = ''
        for module in modules:
            m = re.search('module: ' + module, log, re.M | re.S)
            if m is None:
                missed_module = module
                break

        self._stop()
        shutil.rmtree(self.testdir)

        if missed_module:
            raise unittest.SkipTest('Unit has no ' + missed_module + ' module')

    def check_version(self, version):
        with open(self.pardir + '/src/nxt_main.h' , 'r') as f:
            m = re.search('NXT_VERSION\s+"(\d+\.\d+)"', f.read(), re.M | re.S)

            current = m.group(1).split('.')
            need = version.split('.')

            for i in range(len(need)):
                if need[i] > current[i]:
                    raise unittest.SkipTest('Unit too old')

    def _run(self):
        self.testdir = tempfile.mkdtemp(prefix='unit-test-')

        os.mkdir(self.testdir + '/state')

        print()

        def _run_unit():
            call([self.pardir + '/build/unitd',
                '--no-daemon',
                '--modules', self.pardir + '/build',
                '--state', self.testdir + '/state',
                '--pid', self.testdir + '/unit.pid',
                '--log', self.testdir + '/unit.log',
                '--control', 'unix:' + self.testdir + '/control.unit.sock'])

        self._p = Process(target=_run_unit)
        self._p.start()

        if not self._waitforfiles(self.testdir + '/unit.pid',
            self.testdir + '/unit.log', self.testdir + '/control.unit.sock'):
            exit("Could not start unit")

    def python_application(self, name, code):
        os.mkdir(self.testdir + '/' + name)

        with open(self.testdir + '/' + name + '/wsgi.py', 'w') as f:
            f.write(code)

    def _stop(self):
        with open(self.testdir + '/unit.pid', 'r') as f:
            pid = f.read().rstrip()

        call(['kill', pid])

        for i in range(50):
            if not os.path.exists(self.testdir + '/unit.pid'):
                break
            time.sleep(0.1)

        if os.path.exists(self.testdir + '/unit.pid'):
            exit("Could not terminate unit")

        self._p.join(timeout=1)
        self._terminate_process(self._p)

    def _terminate_process(self, process):
        if process.is_alive():
            process.terminate()
            process.join(timeout=5)

            if process.is_alive():
                exit("Could not terminate process " + process.pid)

        if process.exitcode:
            exit("Child process terminated with code " + str(process.exitcode))

    def _waitforfiles(self, *files):
        for i in range(50):
            wait = False
            ret = 0

            for f in files:
                if not os.path.exists(f):
                   wait = True
                   break

            if wait:
                time.sleep(0.1)

            else:
                ret = 1
                break

        return ret

class TestUnitControl(TestUnit):

    # TODO socket reuse
    # TODO http client

    def conf(self, conf, path='/'):
        if isinstance(conf, dict):
            conf = json.dumps(conf)

        return self._body_json(self.put(path, conf))

    def conf_get(self, path='/'):
        return self._body_json(self.get(path))

    def conf_delete(self, path='/'):
        return self._body_json(self.delete(path))

    def http(self, req):
        with self._control_sock() as sock:
            sock.sendall(req)

            if '--verbose' in sys.argv:
                print('>>>', req, sep='\n')

            resp = self._recvall(sock)

            if '--verbose' in sys.argv:
                print('<<<', resp, sep='\n')

        return resp

    def get(self, path='/'):
        resp = self.http(('GET ' + path
            + ' HTTP/1.1\r\nHost: localhost\r\n\r\n').encode())

        return resp

    def delete(self, path='/'):
        resp = self.http(('DELETE ' + path
            + ' HTTP/1.1\r\nHost: localhost\r\n\r\n').encode())

        return resp

    def put(self, path='/', data=''):
        if isinstance(data, str):
            data = data.encode()

        resp = self.http(('PUT ' + path + ' HTTP/1.1\nHost: localhost\n'
            + 'Content-Length: ' + str(len(data))
            + '\r\n\r\n').encode() + data)

        return resp

    def _control_sock(self):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(self.testdir + '/control.unit.sock')
        return sock

    def _recvall(self, sock, buff_size=4096):
        data = ''
        while True:
            part = sock.recv(buff_size).decode()
            data += part
            if len(part) < buff_size:
                break

        return data

    def _body_json(self, resp):
        m = re.search('.*?\x0d\x0a?\x0d\x0a?(.*)', resp, re.M | re.S)
        return json.loads(m.group(1))

class TestUnitHTTP():

    @classmethod
    def http(self, method, **kwargs):
        host = '127.0.0.1:7080' if 'host' not in kwargs else kwargs['host']
        uri = '/' if 'uri' not in kwargs else kwargs['uri']
        sess = Session() if 'sess' not in kwargs else kwargs['sess']
        data = None if 'data' not in kwargs else kwargs['data']
        headers = None if 'headers' not in kwargs else kwargs['headers']

        req = Request(method, 'http://' + host + uri, data=data,
            headers=headers)

        r = sess.send(req.prepare())

        if 'keep' not in kwargs:
            sess.close()
            return r

        return (r, sess)

    def get(**kwargs):
        return TestUnitHTTP.http('GET', **kwargs)

    def post(**kwargs):
        return TestUnitHTTP.http('POST', **kwargs)
