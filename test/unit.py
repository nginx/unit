import os
import re
import ssl
import sys
import json
import time
import shutil
import socket
import select
import argparse
import platform
import tempfile
import unittest
import subprocess
from multiprocessing import Process

class TestUnit(unittest.TestCase):

    pardir = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
    architecture = platform.architecture()[0]
    maxDiff = None

    detailed = False
    save_log = False

    def __init__(self, methodName='runTest'):
        super().__init__(methodName)

        if re.match(r'.*\/run\.py$', sys.argv[0]):
            args, rest = TestUnit._parse_args()

            TestUnit._set_args(args)

    @classmethod
    def main(cls):
        args, rest = TestUnit._parse_args()

        for i, arg in enumerate(rest):
            if arg[:5] == 'test_':
                rest[i] = cls.__name__ + '.' + arg

        sys.argv = sys.argv[:1] + rest

        TestUnit._set_args(args)

        unittest.main()

    def setUp(self):
        self._run()

    def tearDown(self):
        self.stop()

        # detect errors and failures for current test

        def list2reason(exc_list):
            if exc_list and exc_list[-1][0] is self:
                return exc_list[-1][1]

        if hasattr(self, '_outcome'):
            result = self.defaultTestResult()
            self._feedErrorsToResult(result, self._outcome.errors)
        else:
            result = getattr(self, '_outcomeForDoCleanups',
                self._resultForDoCleanups)

        success = not list2reason(result.errors) \
              and not list2reason(result.failures)

        # check unit.log for alerts

        with open(self.testdir + '/unit.log', 'r', encoding='utf-8',
            errors='ignore') as f:
            self._check_alerts(f.read())

        # remove unit.log

        if not TestUnit.save_log and success:
            shutil.rmtree(self.testdir)

        else:
            self._print_path_to_log()

    def check_modules(self, *modules):
        self._run()

        for i in range(50):
            with open(self.testdir + '/unit.log', 'r') as f:
                log = f.read()
                m = re.search('controller started', log)

                if m is None:
                    time.sleep(0.1)
                else:
                    break

        if m is None:
            self.stop()
            exit("Unit is writing log too long")

        current_dir = os.path.dirname(os.path.abspath(__file__))

        missed_module = ''
        for module in modules:
            if module == 'go':
                env = os.environ.copy()
                env['GOPATH'] = self.pardir + '/go'

                try:
                    process = subprocess.Popen(['go', 'build', '-o',
                        self.testdir + '/go/check_module',
                        current_dir + '/go/empty/app.go'], env=env)
                    process.communicate()

                    m = module if process.returncode == 0 else None

                except:
                    m = None

            elif module == 'node':
                if os.path.isdir(self.pardir + '/node/node_modules'):
                    m = module
                else:
                    m = None

            elif module == 'openssl':
                try:
                    subprocess.check_output(['which', 'openssl'])

                    output = subprocess.check_output([
                    self.pardir + '/build/unitd', '--version'],
                    stderr=subprocess.STDOUT)

                    m = re.search('--openssl', output.decode())

                except:
                    m = None

            else:
                m = re.search('module: ' + module, log)

            if m is None:
                missed_module = module
                break

        self.stop()
        self._check_alerts(log)
        shutil.rmtree(self.testdir)

        if missed_module:
            raise unittest.SkipTest('Unit has no ' + missed_module + ' module')

    def stop(self):
        if self._started:
            self._stop()

    def _run(self):
        self.testdir = tempfile.mkdtemp(prefix='unit-test-')

        os.mkdir(self.testdir + '/state')

        print()

        def _run_unit():
            subprocess.call([self.pardir + '/build/unitd',
                '--no-daemon',
                '--modules', self.pardir + '/build',
                '--state', self.testdir + '/state',
                '--pid', self.testdir + '/unit.pid',
                '--log', self.testdir + '/unit.log',
                '--control', 'unix:' + self.testdir + '/control.unit.sock'])

        self._p = Process(target=_run_unit)
        self._p.start()

        if not self.waitforfiles(self.testdir + '/unit.pid',
            self.testdir + '/unit.log', self.testdir + '/control.unit.sock'):
            exit("Could not start unit")

        self._started = True

        self.skip_alerts = [r'read signalfd\(4\) failed', r'sendmsg.+failed',
            r'recvmsg.+failed']
        self.skip_sanitizer = False

    def _stop(self):
        with open(self.testdir + '/unit.pid', 'r') as f:
            pid = f.read().rstrip()

        subprocess.call(['kill', '-s', 'QUIT', pid])

        for i in range(50):
            if not os.path.exists(self.testdir + '/unit.pid'):
                break
            time.sleep(0.1)

        if os.path.exists(self.testdir + '/unit.pid'):
            exit("Could not terminate unit")

        self._started = False

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

    def _check_alerts(self, log):
        found = False

        alerts = re.findall('.+\[alert\].+', log)

        if alerts:
            print('All alerts/sanitizer errors found in log:')
            [print(alert) for alert in alerts]
            found = True

        if self.skip_alerts:
            for skip in self.skip_alerts:
                alerts = [al for al in alerts if re.search(skip, al) is None]

        if alerts:
            self._print_path_to_log()
            self.assertFalse(alerts, 'alert(s)')

        if not self.skip_sanitizer:
            sanitizer_errors = re.findall('.+Sanitizer.+', log)

            if sanitizer_errors:
                self._print_path_to_log()
                self.assertFalse(sanitizer_errors, 'sanitizer error(s)')

        if found:
            print('skipped.')

    def waitforfiles(self, *files):
        for i in range(50):
            wait = False
            ret = False

            for f in files:
                if not os.path.exists(f):
                   wait = True
                   break

            if wait:
                time.sleep(0.1)

            else:
                ret = True
                break

        return ret

    @staticmethod
    def _parse_args():
        parser = argparse.ArgumentParser(add_help=False)

        parser.add_argument('-d', '--detailed', dest='detailed',
            action='store_true',  help='Detailed output for tests')
        parser.add_argument('-l', '--log', dest='save_log',
            action='store_true', help='Save unit.log after the test execution')

        return parser.parse_known_args()

    @staticmethod
    def _set_args(args):
        TestUnit.detailed = args.detailed
        TestUnit.save_log = args.save_log

    def _print_path_to_log(self):
        print('Path to unit.log:\n' + self.testdir + '/unit.log')

class TestUnitHTTP(TestUnit):

    def http(self, start_str, **kwargs):
        sock_type = 'ipv4' if 'sock_type' not in kwargs else kwargs['sock_type']
        port = 7080 if 'port' not in kwargs else kwargs['port']
        url = '/' if 'url' not in kwargs else kwargs['url']
        http = 'HTTP/1.0' if 'http_10' in kwargs else 'HTTP/1.1'

        headers = ({
            'Host': 'localhost',
            'Connection': 'close'
        } if 'headers' not in kwargs else kwargs['headers'])

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

            if sock_type == sock_types['ipv4'] or sock_type == sock_types['ipv6']:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

            if 'wrapper' in kwargs:
                sock = kwargs['wrapper'](sock)

            connect_args = addr if sock_type == 'unix' else (addr, port)
            try:
                sock.connect(connect_args)
            except ConnectionRefusedError:
                sock.close()
                return None

        else:
            sock = kwargs['sock']

        if 'raw' not in kwargs:
            req = ' '.join([start_str, url, http]) + crlf

            if body is not b'':
                if isinstance(body, str):
                    body = body.encode()

                if 'Content-Length' not in headers:
                    headers['Content-Length'] = len(body)

            for header, value in headers.items():
                if isinstance(value, list):
                    for v in value:
                        req += header + ': ' + str(v) + crlf

                else:
                    req += header + ': ' + str(value) + crlf

            req = (req + crlf).encode() + body

        else:
            req = start_str

        sock.sendall(req)

        if TestUnit.detailed:
            print('>>>', req, sep='\n')

        resp = ''

        if 'no_recv' not in kwargs:
            enc = 'utf-8' if 'encoding' not in kwargs else kwargs['encoding']
            read_timeout = 5 if 'read_timeout' not in kwargs else kwargs['read_timeout']
            resp = self.recvall(sock, read_timeout=read_timeout).decode(enc)

        if TestUnit.detailed:
            print('<<<', resp.encode('utf-8'), sep='\n')

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

    def recvall(self, sock, read_timeout=5, buff_size=4096):
        data = b''
        while select.select([sock], [], [], read_timeout)[0]:
            try:
                part = sock.recv(buff_size)
            except:
                break

            data += part

            if not len(part):
                break

        return data

    def _resp_to_dict(self, resp):
        m = re.search('(.*?\x0d\x0a?)\x0d\x0a?(.*)', resp, re.M | re.S)

        if not m:
            return {}

        headers_text, body = m.group(1), m.group(2)

        p = re.compile('(.*?)\x0d\x0a?', re.M | re.S)
        headers_lines = p.findall(headers_text)

        status = re.search('^HTTP\/\d\.\d\s(\d+)|$', headers_lines.pop(0)).group(1)

        headers = {}
        for line in headers_lines:
            m = re.search('(.*)\:\s(.*)', line)

            if m.group(1) not in headers:
                headers[m.group(1)] = m.group(2)
            elif isinstance(headers[m.group(1)], list):
                headers[m.group(1)].append(m.group(2))
            else:
                headers[m.group(1)] = [headers[m.group(1)], m.group(2)]

        return {
            'status': int(status),
            'headers': headers,
            'body': body
        }

class TestUnitControl(TestUnitHTTP):

    # TODO socket reuse
    # TODO http client

    def conf(self, conf, path='/config'):
        if isinstance(conf, dict) or isinstance(conf, list):
            conf = json.dumps(conf)

        if path[:1] != '/':
            path = '/config/' + path

        return json.loads(self.put(
            url=path,
            body=conf,
            sock_type='unix',
            addr=self.testdir + '/control.unit.sock'
        )['body'])

    def conf_get(self, path='/config'):
        if path[:1] != '/':
            path = '/config/' + path

        return json.loads(self.get(
            url=path,
            sock_type='unix',
            addr=self.testdir + '/control.unit.sock'
        )['body'])

    def conf_delete(self, path='/config'):
        if path[:1] != '/':
            path = '/config/' + path

        return json.loads(self.delete(
            url=path,
            sock_type='unix',
            addr=self.testdir + '/control.unit.sock'
        )['body'])

class TestUnitApplicationProto(TestUnitControl):

    current_dir = os.path.dirname(os.path.abspath(__file__))

    def sec_epoch(self):
        return time.mktime(time.gmtime())

    def date_to_sec_epoch(self, date, template='%a, %d %b %Y %H:%M:%S %Z'):
        return time.mktime(time.strptime(date, template))

    def search_in_log(self, pattern):
        with open(self.testdir + '/unit.log', 'r', errors='ignore') as f:
            return re.search(pattern, f.read())

class TestUnitApplicationPython(TestUnitApplicationProto):
    def load(self, script, name=None):
        if name is None:
            name = script

        self.conf({
            "listeners": {
                "*:7080": {
                    "application": name
                }
            },
            "applications": {
                name: {
                    "type": "python",
                    "processes": { "spare": 0 },
                    "path": self.current_dir + '/python/' + script,
                    "working_directory": self.current_dir + '/python/' + script,
                    "module": "wsgi"
                }
            }
        })

class TestUnitApplicationRuby(TestUnitApplicationProto):
    def load(self, script, name='config.ru'):
        self.conf({
            "listeners": {
                "*:7080": {
                    "application": script
                }
            },
            "applications": {
                script: {
                    "type": "ruby",
                    "processes": { "spare": 0 },
                    "working_directory": self.current_dir + '/ruby/' + script,
                    "script": self.current_dir + '/ruby/' + script + '/' + name
                }
            }
        })

class TestUnitApplicationPHP(TestUnitApplicationProto):
    def load(self, script, name='index.php'):
        self.conf({
            "listeners": {
                "*:7080": {
                    "application": script
                }
            },
            "applications": {
                script: {
                    "type": "php",
                    "processes": { "spare": 0 },
                    "root": self.current_dir + '/php/' + script,
                    "working_directory": self.current_dir + '/php/' + script,
                    "index": name
                }
            }
        })

class TestUnitApplicationGo(TestUnitApplicationProto):
    def load(self, script, name='app'):

        if not os.path.isdir(self.testdir + '/go'):
            os.mkdir(self.testdir + '/go')

        env = os.environ.copy()
        env['GOPATH'] = self.pardir + '/go'
        process = subprocess.Popen(['go', 'build', '-o',
            self.testdir + '/go/' + name,
            self.current_dir + '/go/' + script + '/' + name + '.go'],
            env=env)
        process.communicate()

        self.conf({
            "listeners": {
                "*:7080": {
                    "application": script
                }
            },
            "applications": {
                script: {
                    "type": "external",
                    "processes": { "spare": 0 },
                    "working_directory": self.current_dir + '/go/' + script,
                    "executable": self.testdir + '/go/' + name
                }
            }
        })

class TestUnitApplicationNode(TestUnitApplicationProto):
    def load(self, script, name='app.js'):

        # copy application

        shutil.copytree(self.current_dir + '/node/' + script,
            self.testdir + '/node')

        # link modules

        os.symlink(self.pardir + '/node/node_modules',
            self.testdir + '/node/node_modules')

        self.conf({
            "listeners": {
                "*:7080": {
                    "application": script
                }
            },
            "applications": {
                script: {
                    "type": "external",
                    "processes": { "spare": 0 },
                    "working_directory": self.testdir + '/node',
                    "executable": name
                }
            }
        })

class TestUnitApplicationJava(TestUnitApplicationProto):
    def load(self, script, name='app'):

        app_path = self.testdir + '/java'
        web_inf_path = app_path + '/WEB-INF/'
        classes_path = web_inf_path + 'classes/'

        script_path = self.current_dir + '/java/' + script + '/'

        if not os.path.isdir(app_path):
            os.makedirs(app_path)

        src = []

        for f in os.listdir(script_path):
            if f.endswith('.java'):
                src.append(script_path + f)
                continue

            if f.startswith('.') or f == 'Makefile':
                continue

            if os.path.isdir(script_path + f):
                if f == 'WEB-INF':
                    continue

                shutil.copytree(script_path + f, app_path + '/' + f)
                continue

            if f == 'web.xml':
                if not os.path.isdir(web_inf_path):
                    os.makedirs(web_inf_path)

                shutil.copy2(script_path + f, web_inf_path)
            else:
                shutil.copy2(script_path + f, app_path)

        if src:
            if not os.path.isdir(classes_path):
                os.makedirs(classes_path)

            javac = ['javac', '-encoding', 'utf-8', '-d', classes_path,
                '-classpath',
                self.pardir + '/build/tomcat-servlet-api-9.0.13.jar']
            javac.extend(src)

            process = subprocess.Popen(javac)
            process.communicate()

        self.conf({
            "listeners": {
                "*:7080": {
                    "application": script
                }
            },
            "applications": {
                script: {
                    "unit_jars": self.pardir + '/build',
                    "type": "java",
                    "processes": { "spare": 0 },
                    "working_directory": script_path,
                    "webapp": app_path
                }
            }
        })

class TestUnitApplicationPerl(TestUnitApplicationProto):
    def load(self, script, name='psgi.pl'):
        self.conf({
            "listeners": {
                "*:7080": {
                    "application": script
                }
            },
            "applications": {
                script: {
                    "type": "perl",
                    "processes": { "spare": 0 },
                    "working_directory": self.current_dir + '/perl/' + script,
                    "script": self.current_dir + '/perl/' + script + '/' + name
                }
            }
        })

class TestUnitApplicationTLS(TestUnitApplicationProto):
    def __init__(self, test):
        super().__init__(test)

        self.context = ssl.create_default_context()
        self.context.check_hostname = False
        self.context.verify_mode = ssl.CERT_NONE

    def certificate(self, name='default', load=True):
        subprocess.call(['openssl', 'req', '-x509', '-new', '-config',
            self.testdir + '/openssl.conf', '-subj', '/CN=' + name + '/',
            '-out', self.testdir + '/' + name + '.crt',
            '-keyout', self.testdir + '/' + name + '.key'])

        if load:
            self.certificate_load(name)

    def certificate_load(self, crt, key=None):
        if key is None:
            key = crt

        with open(self.testdir + '/' + key + '.key', 'rb') as k, \
             open(self.testdir + '/' + crt + '.crt', 'rb') as c:
                return self.conf(k.read() + c.read(), '/certificates/' + crt)

    def get_ssl(self, **kwargs):
        return self.get(wrapper=self.context.wrap_socket,
            **kwargs)

    def post_ssl(self, **kwargs):
        return self.post(wrapper=self.context.wrap_socket,
            **kwargs)

    def get_server_certificate(self, addr=('127.0.0.1', 7080)):
        return ssl.get_server_certificate(addr)

    def load(self, script, name=None):
        if name is None:
            name = script

        # create default openssl configuration

        with open(self.testdir + '/openssl.conf', 'w') as f:
            f.write("""[ req ]
default_bits = 1024
encrypt_key = no
distinguished_name = req_distinguished_name
[ req_distinguished_name ]""")

        self.conf({
            "listeners": {
                "*:7080": {
                    "application": name
                }
            },
            "applications": {
                name: {
                    "type": "python",
                    "processes": { "spare": 0 },
                    "path": self.current_dir + '/python/' + script,
                    "working_directory": self.current_dir + '/python/' + script,
                    "module": "wsgi"
                }
            }
        })
