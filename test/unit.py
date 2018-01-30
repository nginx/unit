import os
import re
import sys
import json
import time
import shutil
import socket
import select
import tempfile
import unittest
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

class TestUnitHTTP(TestUnit):

    def http(self, start_str, **kwargs):
        sock_type = 'ipv4' if 'sock_type' not in kwargs else kwargs['sock_type']
        port = 7080 if 'port' not in kwargs else kwargs['port']
        url = '/' if 'url' not in kwargs else kwargs['url']
        http = 'HTTP/1.0' if 'http_10' in kwargs else 'HTTP/1.1'
        headers = {'Host': 'localhost'} if 'headers' not in kwargs else kwargs['headers']
        body = b'' if 'body' not in kwargs else kwargs['body']
        crlf = '\r\n'

        if 'addr' not in kwargs:
            addr = '::1' if sock_type == 'ipv6' else '127.0.0.1'
        else:
            addr = kwargs['addr']

        sock_types = {
            'ipv4': socket.AF_INET,
            'ipv6': socket.AF_INET6,
            'unix': socket.AF_UNIX
        }

        if 'sock' not in kwargs:
            sock = socket.socket(sock_types[sock_type], socket.SOCK_STREAM)

            if sock_type == 'unix':
                sock.connect(addr)
            else:
                sock.connect((addr, port))

        else:
            sock = kwargs['sock']

        sock.setblocking(False)

        if 'raw' not in kwargs:
            req = ' '.join([start_str, url, http]) + crlf

            if body is not b'':
                if isinstance(body, str):
                    body = body.encode()

                if 'Content-Length' not in headers:
                    headers['Content-Length'] = len(body)

            for header, value in headers.items():
                req += header + ': ' + str(value) + crlf

            req = (req + crlf).encode() + body

        else:
            req = start_str

        sock.sendall(req)

        if '--verbose' in sys.argv:
            print('>>>', req, sep='\n')

        resp = self._recvall(sock)

        if '--verbose' in sys.argv:
            print('<<<', resp, sep='\n')

        if 'raw_resp' not in kwargs:
            resp = self._resp_to_dict(resp)

        if 'start' not in kwargs:
            sock.close()
            return resp

        return (resp, sock)

    def delete(self, **kwargs):
        return self.http('DELETE', **kwargs)

    def get(self, **kwargs):
        return self.http('GET', **kwargs)

    def post(self, **kwargs):
        return self.http('POST', **kwargs)

    def put(self, **kwargs):
        return self.http('PUT', **kwargs)

    def _recvall(self, sock, buff_size=4096):
        data = ''
        while select.select([sock], [], [], 1)[0]:
            part = sock.recv(buff_size).decode()
            data += part
            if part is '':
                break

        return data

    def _resp_to_dict(self, resp):
        m = re.search('(.*?\x0d\x0a?)\x0d\x0a?(.*)', resp, re.M | re.S)
        headers_text, body = m.group(1), m.group(2)

        p = re.compile('(.*?)\x0d\x0a?', re.M | re.S)
        headers_lines = p.findall(headers_text)

        status = re.search('^HTTP\/\d\.\d\s(\d+)|$', headers_lines.pop(0)).group(1)

        headers = {}
        for line in headers_lines:
            m = re.search('(.*)\:\s(.*)', line)
            headers[m.group(1)] = m.group(2)

        return {
            'status': int(status),
            'headers': headers,
            'body': body
        }

class TestUnitControl(TestUnitHTTP):

    # TODO socket reuse
    # TODO http client

    def conf(self, conf, path='/'):
        if isinstance(conf, dict):
            conf = json.dumps(conf)

        return json.loads(self.put(
            url=path,
            body=conf,
            sock_type='unix',
            addr=self.testdir + '/control.unit.sock'
        )['body'])

    def conf_get(self, path='/'):
        return json.loads(self.get(
            url=path,
            sock_type='unix',
            addr=self.testdir + '/control.unit.sock'
        )['body'])

    def conf_delete(self, path='/'):
        return json.loads(self.delete(
            url=path,
            sock_type='unix',
            addr=self.testdir + '/control.unit.sock'
        )['body'])
