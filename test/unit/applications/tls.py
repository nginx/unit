import os
import ssl
import subprocess

from unit.applications.proto import TestApplicationProto
from unit.option import option


class TestApplicationTLS(TestApplicationProto):
    def setup_method(self):
        self.context = ssl.create_default_context()
        self.context.check_hostname = False
        self.context.verify_mode = ssl.CERT_NONE

    def certificate(self, name='default', load=True):
        self.openssl_conf()

        subprocess.check_output(
            [
                'openssl',
                'req',
                '-x509',
                '-new',
                '-subj',
                f'/CN={name}/',
                '-config',
                f'{option.temp_dir}/openssl.conf',
                '-out',
                f'{option.temp_dir}/{name}.crt',
                '-keyout',
                f'{option.temp_dir}/{name}.key',
            ],
            stderr=subprocess.STDOUT,
        )

        if load:
            self.certificate_load(name)

    def certificate_load(self, crt, key=None):
        if key is None:
            key = crt

        key_path = f'{option.temp_dir}/{key}.key'
        crt_path = f'{option.temp_dir}/{crt}.crt'

        with open(key_path, 'rb') as k, open(crt_path, 'rb') as c:
            return self.conf(k.read() + c.read(), f'/certificates/{crt}')

    def get_ssl(self, **kwargs):
        return self.get(wrapper=self.context.wrap_socket, **kwargs)

    def post_ssl(self, **kwargs):
        return self.post(wrapper=self.context.wrap_socket, **kwargs)

    def openssl_conf(self, rewrite=False, alt_names=None):
        alt_names = alt_names or []
        conf_path = f'{option.temp_dir}/openssl.conf'

        if not rewrite and os.path.exists(conf_path):
            return

        # Generates alt_names section with dns names
        a_names = '[alt_names]\n'
        for i, k in enumerate(alt_names, 1):
            k = k.split('|')

            if k[0] == 'IP':
                a_names += f'IP.{i} = {k[1]}\n'
            else:
                a_names += f'DNS.{i} = {k[0]}\n'

        # Generates section for sign request extension
        a_sec = f'''req_extensions = myca_req_extensions

[ myca_req_extensions ]
subjectAltName = @alt_names

{a_names}'''

        with open(conf_path, 'w') as f:
            f.write(
                f'''[ req ]
default_bits = 2048
encrypt_key = no
distinguished_name = req_distinguished_name

{a_sec if alt_names else ""}
[ req_distinguished_name ]'''
            )

    def load(self, script, name=None):
        if name is None:
            name = script

        script_path = f'{option.test_dir}/python/{script}'
        self._load_conf(
            {
                "listeners": {"*:7080": {"pass": f"applications/{name}"}},
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
