import os
import ssl
import subprocess
from unit.applications.proto import TestApplicationProto


class TestApplicationTLS(TestApplicationProto):
    def __init__(self, test):
        super().__init__(test)

        self.context = ssl.create_default_context()
        self.context.check_hostname = False
        self.context.verify_mode = ssl.CERT_NONE

    def certificate(self, name='default', load=True):
        self.openssl_conf()

        subprocess.call(
            [
                'openssl',
                'req',
                '-x509',
                '-new',
                '-subj',    '/CN=' + name + '/',
                '-config',  self.testdir + '/openssl.conf',
                '-out',     self.testdir + '/' + name + '.crt',
                '-keyout',  self.testdir + '/' + name + '.key',
            ]
        )

        if load:
            self.certificate_load(name)

    def certificate_load(self, crt, key=None):
        if key is None:
            key = crt

        key_path = self.testdir + '/' + key + '.key'
        crt_path = self.testdir + '/' + crt + '.crt'

        with open(key_path, 'rb') as k, open(crt_path, 'rb') as c:
            return self.conf(k.read() + c.read(), '/certificates/' + crt)

    def get_ssl(self, **kwargs):
        return self.get(wrapper=self.context.wrap_socket, **kwargs)

    def post_ssl(self, **kwargs):
        return self.post(wrapper=self.context.wrap_socket, **kwargs)

    def get_server_certificate(self, addr=('127.0.0.1', 7080)):

        ssl_list = dir(ssl)

        if 'PROTOCOL_TLS' in ssl_list:
            ssl_version = ssl.PROTOCOL_TLS

        elif 'PROTOCOL_TLSv1_2' in ssl_list:
            ssl_version = ssl.PROTOCOL_TLSv1_2

        else:
            ssl_version = ssl.PROTOCOL_TLSv1_1

        return ssl.get_server_certificate(addr, ssl_version=ssl_version)

    def openssl_conf(self):
        conf_path = self.testdir + '/openssl.conf'

        if os.path.exists(conf_path):
            return

        with open(conf_path, 'w') as f:
            f.write(
                """[ req ]
default_bits = 2048
encrypt_key = no
distinguished_name = req_distinguished_name
[ req_distinguished_name ]"""
            )

    def load(self, script, name=None):
        if name is None:
            name = script

        script_path = self.current_dir + '/python/' + script

        self._load_conf(
            {
                "listeners": {"*:7080": {"pass": "applications/" + name}},
                "applications": {
                    name: {
                        "type": "python",
                        "processes": {"spare": 0},
                        "path": script_path,
                        "working_directory": script_path,
                        "module": "wsgi",
                    }
                },
            }
        )
