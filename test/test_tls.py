import io
import ssl
import subprocess
import time

import pytest
from unit.applications.tls import TestApplicationTLS
from unit.option import option


class TestTLS(TestApplicationTLS):
    prerequisites = {'modules': {'python': 'any', 'openssl': 'any'}}

    def openssl_date_to_sec_epoch(self, date):
        return self.date_to_sec_epoch(date, '%b %d %X %Y %Z')

    def add_tls(self, application='empty', cert='default', port=7080):
        assert 'success' in self.conf(
            {
                "pass": "applications/" + application,
                "tls": {"certificate": cert},
            },
            'listeners/*:' + str(port),
        )

    def remove_tls(self, application='empty', port=7080):
        assert 'success' in self.conf(
            {"pass": "applications/" + application}, 'listeners/*:' + str(port)
        )

    def req(self, name='localhost', subject=None, x509=False):
        subj = subject if subject is not None else '/CN=' + name + '/'

        subprocess.check_output(
            [
                'openssl',
                'req',
                '-new',
                '-subj',
                subj,
                '-config',
                option.temp_dir + '/openssl.conf',
                '-out',
                option.temp_dir + '/' + name + '.csr',
                '-keyout',
                option.temp_dir + '/' + name + '.key',
            ],
            stderr=subprocess.STDOUT,
        )

    def generate_ca_conf(self):
        with open(option.temp_dir + '/ca.conf', 'w') as f:
            f.write(
                """[ ca ]
default_ca = myca

[ myca ]
new_certs_dir = %(dir)s
database = %(database)s
default_md = sha256
policy = myca_policy
serial = %(certserial)s
default_days = 1
x509_extensions = myca_extensions
copy_extensions = copy

[ myca_policy ]
commonName = optional

[ myca_extensions ]
basicConstraints = critical,CA:TRUE"""
                % {
                    'dir': option.temp_dir,
                    'database': option.temp_dir + '/certindex',
                    'certserial': option.temp_dir + '/certserial',
                }
            )

        with open(option.temp_dir + '/certserial', 'w') as f:
            f.write('1000')

        with open(option.temp_dir + '/certindex', 'w') as f:
            f.write('')

        with open(option.temp_dir + '/certindex.attr', 'w') as f:
            f.write('')

    def ca(self, cert='root', out='localhost'):
        subprocess.check_output(
            [
                'openssl',
                'ca',
                '-batch',
                '-config',
                option.temp_dir + '/ca.conf',
                '-keyfile',
                option.temp_dir + '/' + cert + '.key',
                '-cert',
                option.temp_dir + '/' + cert + '.crt',
                '-in',
                option.temp_dir + '/' + out + '.csr',
                '-out',
                option.temp_dir + '/' + out + '.crt',
            ],
            stderr=subprocess.STDOUT,
        )

    def set_certificate_req_context(self, cert='root'):
        self.context = ssl.create_default_context()
        self.context.check_hostname = False
        self.context.verify_mode = ssl.CERT_REQUIRED
        self.context.load_verify_locations(
            option.temp_dir + '/' + cert + '.crt'
        )

    def test_tls_listener_option_add(self):
        self.load('empty')

        self.certificate()

        self.add_tls()

        assert self.get_ssl()['status'] == 200, 'add listener option'

    def test_tls_listener_option_remove(self):
        self.load('empty')

        self.certificate()

        self.add_tls()

        self.get_ssl()

        self.remove_tls()

        assert self.get()['status'] == 200, 'remove listener option'

    def test_tls_certificate_remove(self):
        self.load('empty')

        self.certificate()

        assert 'success' in self.conf_delete(
            '/certificates/default'
        ), 'remove certificate'

    def test_tls_certificate_remove_used(self):
        self.load('empty')

        self.certificate()

        self.add_tls()

        assert 'error' in self.conf_delete(
            '/certificates/default'
        ), 'remove certificate'

    def test_tls_certificate_remove_nonexisting(self):
        self.load('empty')

        self.certificate()

        self.add_tls()

        assert 'error' in self.conf_delete(
            '/certificates/blah'
        ), 'remove nonexistings certificate'

    @pytest.mark.skip('not yet')
    def test_tls_certificate_update(self):
        self.load('empty')

        self.certificate()

        self.add_tls()

        cert_old = ssl.get_server_certificate(('127.0.0.1', 7080))

        self.certificate()

        assert cert_old != ssl.get_server_certificate(
            ('127.0.0.1', 7080)
        ), 'update certificate'

    @pytest.mark.skip('not yet')
    def test_tls_certificate_key_incorrect(self):
        self.load('empty')

        self.certificate('first', False)
        self.certificate('second', False)

        assert 'error' in self.certificate_load(
            'first', 'second'
        ), 'key incorrect'

    def test_tls_certificate_change(self):
        self.load('empty')

        self.certificate()
        self.certificate('new')

        self.add_tls()

        cert_old = ssl.get_server_certificate(('127.0.0.1', 7080))

        self.add_tls(cert='new')

        assert cert_old != ssl.get_server_certificate(
            ('127.0.0.1', 7080)
        ), 'change certificate'

    def test_tls_certificate_key_rsa(self):
        self.load('empty')

        self.certificate()

        assert (
            self.conf_get('/certificates/default/key') == 'RSA (2048 bits)'
        ), 'certificate key rsa'

    def test_tls_certificate_key_ec(self, temp_dir):
        self.load('empty')

        self.openssl_conf()

        subprocess.check_output(
            [
                'openssl',
                'ecparam',
                '-noout',
                '-genkey',
                '-out',
                temp_dir + '/ec.key',
                '-name',
                'prime256v1',
            ],
            stderr=subprocess.STDOUT,
        )

        subprocess.check_output(
            [
                'openssl',
                'req',
                '-x509',
                '-new',
                '-subj',
                '/CN=ec/',
                '-config',
                temp_dir + '/openssl.conf',
                '-key',
                temp_dir + '/ec.key',
                '-out',
                temp_dir + '/ec.crt',
            ],
            stderr=subprocess.STDOUT,
        )

        self.certificate_load('ec')

        assert (
            self.conf_get('/certificates/ec/key') == 'ECDH'
        ), 'certificate key ec'

    def test_tls_certificate_chain_options(self):
        self.load('empty')

        self.certificate()

        chain = self.conf_get('/certificates/default/chain')

        assert len(chain) == 1, 'certificate chain length'

        cert = chain[0]

        assert (
            cert['subject']['common_name'] == 'default'
        ), 'certificate subject common name'
        assert (
            cert['issuer']['common_name'] == 'default'
        ), 'certificate issuer common name'

        assert (
            abs(
                self.sec_epoch()
                - self.openssl_date_to_sec_epoch(cert['validity']['since'])
            )
            < 60
        ), 'certificate validity since'
        assert (
            self.openssl_date_to_sec_epoch(cert['validity']['until'])
            - self.openssl_date_to_sec_epoch(cert['validity']['since'])
            == 2592000
        ), 'certificate validity until'

    def test_tls_certificate_chain(self, temp_dir):
        self.load('empty')

        self.certificate('root', False)

        self.req('int')
        self.req('end')

        self.generate_ca_conf()

        self.ca(cert='root', out='int')
        self.ca(cert='int', out='end')

        crt_path = temp_dir + '/end-int.crt'
        end_path = temp_dir + '/end.crt'
        int_path = temp_dir + '/int.crt'

        with open(crt_path, 'wb') as crt, open(end_path, 'rb') as end, open(
            int_path, 'rb'
        ) as int:
            crt.write(end.read() + int.read())

        self.set_certificate_req_context()

        # incomplete chain

        assert 'success' in self.certificate_load(
            'end', 'end'
        ), 'certificate chain end upload'

        chain = self.conf_get('/certificates/end/chain')
        assert len(chain) == 1, 'certificate chain end length'
        assert (
            chain[0]['subject']['common_name'] == 'end'
        ), 'certificate chain end subject common name'
        assert (
            chain[0]['issuer']['common_name'] == 'int'
        ), 'certificate chain end issuer common name'

        self.add_tls(cert='end')

        try:
            resp = self.get_ssl()
        except ssl.SSLError:
            resp = None

        assert resp == None, 'certificate chain incomplete chain'

        # intermediate

        assert 'success' in self.certificate_load(
            'int', 'int'
        ), 'certificate chain int upload'

        chain = self.conf_get('/certificates/int/chain')
        assert len(chain) == 1, 'certificate chain int length'
        assert (
            chain[0]['subject']['common_name'] == 'int'
        ), 'certificate chain int subject common name'
        assert (
            chain[0]['issuer']['common_name'] == 'root'
        ), 'certificate chain int issuer common name'

        self.add_tls(cert='int')

        assert self.get_ssl()['status'] == 200, 'certificate chain intermediate'

        # intermediate server

        assert 'success' in self.certificate_load(
            'end-int', 'end'
        ), 'certificate chain end-int upload'

        chain = self.conf_get('/certificates/end-int/chain')
        assert len(chain) == 2, 'certificate chain end-int length'
        assert (
            chain[0]['subject']['common_name'] == 'end'
        ), 'certificate chain end-int int subject common name'
        assert (
            chain[0]['issuer']['common_name'] == 'int'
        ), 'certificate chain end-int int issuer common name'
        assert (
            chain[1]['subject']['common_name'] == 'int'
        ), 'certificate chain end-int end subject common name'
        assert (
            chain[1]['issuer']['common_name'] == 'root'
        ), 'certificate chain end-int end issuer common name'

        self.add_tls(cert='end-int')

        assert (
            self.get_ssl()['status'] == 200
        ), 'certificate chain intermediate server'

    def test_tls_certificate_chain_long(self, temp_dir):
        self.load('empty')

        self.generate_ca_conf()

        # Minimum chain length is 3.
        chain_length = 10

        for i in range(chain_length):
            if i == 0:
                self.certificate('root', False)
            elif i == chain_length - 1:
                self.req('end')
            else:
                self.req('int{}'.format(i))

        for i in range(chain_length - 1):
            if i == 0:
                self.ca(cert='root', out='int1')
            elif i == chain_length - 2:
                self.ca(cert='int{}'.format(chain_length - 2), out='end')
            else:
                self.ca(cert='int{}'.format(i), out='int{}'.format(i + 1))

        for i in range(chain_length - 1, 0, -1):
            path = temp_dir + (
                '/end.crt' if i == chain_length - 1 else '/int{}.crt'.format(i)
            )

            with open(temp_dir + '/all.crt', 'a') as chain, open(path) as cert:
                chain.write(cert.read())

        self.set_certificate_req_context()

        assert 'success' in self.certificate_load(
            'all', 'end'
        ), 'certificate chain upload'

        chain = self.conf_get('/certificates/all/chain')
        assert len(chain) == chain_length - 1, 'certificate chain length'

        self.add_tls(cert='all')

        assert self.get_ssl()['status'] == 200, 'certificate chain long'

    def test_tls_certificate_empty_cn(self, temp_dir):
        self.certificate('root', False)

        self.req(subject='/')

        self.generate_ca_conf()
        self.ca()

        self.set_certificate_req_context()

        assert 'success' in self.certificate_load('localhost', 'localhost')

        cert = self.conf_get('/certificates/localhost')
        assert cert['chain'][0]['subject'] == {}, 'empty subject'
        assert cert['chain'][0]['issuer']['common_name'] == 'root', 'issuer'

    def test_tls_certificate_empty_cn_san(self, temp_dir):
        self.certificate('root', False)

        self.openssl_conf(
            rewrite=True, alt_names=["example.com", "www.example.net"]
        )

        self.req(subject='/')

        self.generate_ca_conf()
        self.ca()

        self.set_certificate_req_context()

        assert 'success' in self.certificate_load('localhost', 'localhost')

        cert = self.conf_get('/certificates/localhost')
        assert cert['chain'][0]['subject'] == {
            'alt_names': ['example.com', 'www.example.net']
        }, 'subject alt_names'
        assert cert['chain'][0]['issuer']['common_name'] == 'root', 'issuer'

    def test_tls_certificate_empty_cn_san_ip(self):
        self.certificate('root', False)

        self.openssl_conf(
            rewrite=True,
            alt_names=['example.com', 'www.example.net', 'IP|10.0.0.1'],
        )

        self.req(subject='/')

        self.generate_ca_conf()
        self.ca()

        self.set_certificate_req_context()

        assert 'success' in self.certificate_load('localhost', 'localhost')

        cert = self.conf_get('/certificates/localhost')
        assert cert['chain'][0]['subject'] == {
            'alt_names': ['example.com', 'www.example.net']
        }, 'subject alt_names'
        assert cert['chain'][0]['issuer']['common_name'] == 'root', 'issuer'

    def test_tls_keepalive(self):
        self.load('mirror')

        assert self.get()['status'] == 200, 'init'

        self.certificate()

        self.add_tls(application='mirror')

        (resp, sock) = self.post_ssl(
            headers={
                'Host': 'localhost',
                'Connection': 'keep-alive',
            },
            start=True,
            body='0123456789',
            read_timeout=1,
        )

        assert resp['body'] == '0123456789', 'keepalive 1'

        resp = self.post_ssl(
            headers={
                'Host': 'localhost',
                'Connection': 'close',
            },
            sock=sock,
            body='0123456789',
        )

        assert resp['body'] == '0123456789', 'keepalive 2'

    def test_tls_no_close_notify(self):
        self.certificate()

        assert 'success' in self.conf(
            {
                "listeners": {
                    "*:7080": {
                        "pass": "routes",
                        "tls": {"certificate": "default"},
                    }
                },
                "routes": [{"action": {"return": 200}}],
                "applications": {},
            }
        ), 'load application configuration'

        (resp, sock) = self.get_ssl(start=True)

        time.sleep(5)

        sock.close()

    @pytest.mark.skip('not yet')
    def test_tls_keepalive_certificate_remove(self):
        self.load('empty')

        assert self.get()['status'] == 200, 'init'

        self.certificate()

        self.add_tls()

        (resp, sock) = self.get_ssl(
            headers={'Host': 'localhost', 'Connection': 'keep-alive'},
            start=True,
            read_timeout=1,
        )

        assert 'success' in self.conf(
            {"pass": "applications/empty"}, 'listeners/*:7080'
        )
        assert 'success' in self.conf_delete('/certificates/default')

        try:
            resp = self.get_ssl(sock=sock)

        except KeyboardInterrupt:
            raise

        except:
            resp = None

        assert resp == None, 'keepalive remove certificate'

    @pytest.mark.skip('not yet')
    def test_tls_certificates_remove_all(self):
        self.load('empty')

        self.certificate()

        assert 'success' in self.conf_delete(
            '/certificates'
        ), 'remove all certificates'

    def test_tls_application_respawn(self, skip_alert):
        self.load('mirror')

        self.certificate()

        assert 'success' in self.conf('1', 'applications/mirror/processes')

        self.add_tls(application='mirror')

        (_, sock) = self.post_ssl(
            headers={
                'Host': 'localhost',
                'Connection': 'keep-alive',
            },
            start=True,
            body='0123456789',
            read_timeout=1,
        )

        app_id = self.findall(r'(\d+)#\d+ "mirror" application started')[0]

        subprocess.check_output(['kill', '-9', app_id])

        skip_alert(r'process %s exited on signal 9' % app_id)

        self.wait_for_record(
            r' (?!' + app_id + r'#)(\d+)#\d+ "mirror" application started'
        )

        resp = self.post_ssl(sock=sock, body='0123456789')

        assert resp['status'] == 200, 'application respawn status'
        assert resp['body'] == '0123456789', 'application respawn body'

    def test_tls_url_scheme(self):
        self.load('variables')

        assert (
            self.post(
                headers={
                    'Host': 'localhost',
                    'Content-Type': 'text/html',
                    'Custom-Header': '',
                    'Connection': 'close',
                }
            )['headers']['Wsgi-Url-Scheme']
            == 'http'
        ), 'url scheme http'

        self.certificate()

        self.add_tls(application='variables')

        assert (
            self.post_ssl(
                headers={
                    'Host': 'localhost',
                    'Content-Type': 'text/html',
                    'Custom-Header': '',
                    'Connection': 'close',
                }
            )['headers']['Wsgi-Url-Scheme']
            == 'https'
        ), 'url scheme https'

    def test_tls_big_upload(self):
        self.load('upload')

        self.certificate()

        self.add_tls(application='upload')

        filename = 'test.txt'
        data = '0123456789' * 9000

        res = self.post_ssl(
            body={
                'file': {
                    'filename': filename,
                    'type': 'text/plain',
                    'data': io.StringIO(data),
                }
            }
        )
        assert res['status'] == 200, 'status ok'
        assert res['body'] == filename + data

    def test_tls_multi_listener(self):
        self.load('empty')

        self.certificate()

        self.add_tls()
        self.add_tls(port=7081)

        assert self.get_ssl()['status'] == 200, 'listener #1'

        assert self.get_ssl(port=7081)['status'] == 200, 'listener #2'
