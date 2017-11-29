import os
import re
import sys
import json
import time
import shutil
import socket
import tempfile
import unittest
import subprocess

class TestUnit(unittest.TestCase):

    def setUp(self):
        self.testdir = tempfile.mkdtemp(prefix='unit-test-')

        os.mkdir(self.testdir + '/state')

        pardir = os.path.abspath(os.path.join(os.path.dirname(__file__),
            os.pardir))

        print()

        subprocess.call([pardir + '/build/unitd',
        # TODO       '--no-daemon',
            '--modules', pardir + '/build',
            '--state', self.testdir + '/state',
            '--pid', self.testdir + '/unit.pid',
            '--log', self.testdir + '/unit.log',
            '--control', 'unix:' + self.testdir + '/control.unit.sock'])

        if not self._waitforfiles([self.testdir + '/unit.pid',
            self.testdir + '/unit.log', self.testdir + '/control.unit.sock']):
            exit("Could not start unit")

    # TODO dependency check

    def tearDown(self):
        with open(self.testdir + '/unit.pid', 'r') as f:
            pid = f.read().rstrip()

        subprocess.call(['kill', pid])

        for i in range(1, 50):
            if not os.path.exists(self.testdir + '/unit.pid'):
                break
            time.sleep(0.1)

        if os.path.exists(self.testdir + '/unit.pid'):
            exit("Could not terminate unit")

        if '--log' in sys.argv:
            with open(self.testdir + '/unit.log', 'r') as f:
                print(f.read())

        if '--leave' not in sys.argv:
            shutil.rmtree(self.testdir)

    def _waitforfiles(self, files):
        if isinstance(files, str):
            files = [files]

        count = 0
        for i in range(1, 50):
            for f in files:
                if os.path.exists(f):
                   count += 1

            if count == len(files):
                return 1

            count = 0
            time.sleep(0.1)

        return 0

class TestUnitControl(TestUnit):

    # TODO socket reuse
    # TODO http client

    def get(self, path='/'):

        with self._control_sock() as sock:
            sock.sendall(('GET ' + path
                + ' HTTP/1.1\r\nHost: localhost\r\n\r\n').encode())
            r = self._recvall(sock)

        return self._body_json(r)

    def delete(self, path='/'):

        with self._control_sock() as sock:
            sock.sendall(('DELETE ' + path
                + ' HTTP/1.1\r\nHost: localhost\r\n\r\n').encode())
            r = self._recvall(sock)

        return self._body_json(r)

    def put(self, path='/', data=''):

        if isinstance(data, str):
            data = data.encode()

        with self._control_sock() as sock:
            sock.sendall(('PUT ' + path + (' HTTP/1.1\nHost: localhost\n'
                'Content-Length: ') + str(len(data)) + '\r\n\r\n').encode()
                + data)
            r = self._recvall(sock)

        return self._body_json(r)

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
