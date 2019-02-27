import re
import ssl
import time
import subprocess
import unittest
import unit

class TestUnitTLS(unit.TestUnitApplicationTLS):

    def setUpClass():
        unit.TestUnit().check_modules('python', 'openssl')

    def findall(self, pattern):
        with open(self.testdir + '/unit.log', 'r', errors='ignore') as f:
            return re.findall(pattern, f.read())

    def wait_for_record(self, pattern):
        for i in range(50):
            with open(self.testdir + '/unit.log', 'r', errors='ignore') as f:
                if re.search(pattern, f.read()) is not None:
                    break

            time.sleep(0.1)

    def openssl_date_to_sec_epoch(self, date):
        return self.date_to_sec_epoch(date, '%b %d %H:%M:%S %Y %Z')

    def add_tls(self, application='empty', cert='default', port=7080):
        self.conf({
            "application": application,
            "tls": {
                "certificate": cert
            }
        }, 'listeners/*:' + str(port))

    def remove_tls(self, application='empty', port=7080):
        self.conf({
            "application": application
        }, 'listeners/*:' + str(port))

    def test_tls_listener_option_add(self):
        self.load('empty')

        self.certificate()

        self.add_tls()

        self.assertEqual(self.get_ssl()['status'], 200, 'add listener option')

    def test_tls_listener_option_remove(self):
        self.load('empty')

        self.certificate()

        self.add_tls()

        self.get_ssl()

        self.remove_tls()

        self.assertEqual(self.get()['status'], 200, 'remove listener option')

    def test_tls_certificate_remove(self):
        self.load('empty')

        self.certificate()

        self.assertIn('success', self.conf_delete('/certificates/default'),
            'remove certificate')

    def test_tls_certificate_remove_used(self):
        self.load('empty')

        self.certificate()

        self.add_tls()

        self.assertIn('error', self.conf_delete('/certificates/default'),
            'remove certificate')

    def test_tls_certificate_remove_nonexisting(self):
        self.load('empty')

        self.certificate()

        self.add_tls()

        self.assertIn('error', self.conf_delete('/certificates/blah'),
            'remove nonexistings certificate')

    @unittest.expectedFailure
    def test_tls_certificate_update(self):
        self.load('empty')

        self.certificate()

        self.add_tls()

        cert_old = self.get_server_certificate()

        self.certificate()

        self.assertNotEqual(cert_old, self.get_server_certificate(),
            'update certificate')

    @unittest.expectedFailure
    def test_tls_certificate_key_incorrect(self):
        self.load('empty')

        self.certificate('first', False)
        self.certificate('second', False)

        self.assertIn('error', self.certificate_load('first', 'second'),
            'key incorrect')

    def test_tls_certificate_change(self):
        self.load('empty')

        self.certificate()
        self.certificate('new')

        self.add_tls()

        cert_old = self.get_server_certificate()

        self.add_tls(cert='new')

        self.assertNotEqual(cert_old, self.get_server_certificate(),
            'change certificate')

    def test_tls_certificate_key_rsa(self):
        self.load('empty')

        self.certificate()

        self.assertEqual(self.conf_get('/certificates/default/key'),
            'RSA (1024 bits)', 'certificate key rsa')

    def test_tls_certificate_key_ec(self):
        self.load('empty')

        subprocess.call(['openssl', 'ecparam', '-noout', '-genkey',
            '-out', self.testdir + '/ec.key',
            '-name', 'prime256v1'])

        subprocess.call(['openssl', 'req', '-x509', '-new',
            '-config', self.testdir + '/openssl.conf',
            '-key', self.testdir + '/ec.key', '-subj', '/CN=ec/',
            '-out', self.testdir + '/ec.crt'])

        self.certificate_load('ec')

        self.assertEqual(self.conf_get('/certificates/ec/key'), 'ECDH',
            'certificate key ec')

    def test_tls_certificate_chain_options(self):
        self.load('empty')

        self.certificate()

        chain = self.conf_get('/certificates/default/chain')

        self.assertEqual(len(chain), 1, 'certificate chain length')

        cert = chain[0]

        self.assertEqual(cert['subject']['common_name'], 'default',
            'certificate subject common name')
        self.assertEqual(cert['issuer']['common_name'], 'default',
            'certificate issuer common name')

        self.assertLess(abs(self.sec_epoch() -
            self.openssl_date_to_sec_epoch(cert['validity']['since'])), 5,
            'certificate validity since')
        self.assertEqual(
            self.openssl_date_to_sec_epoch(cert['validity']['until']) -
            self.openssl_date_to_sec_epoch(cert['validity']['since']), 2592000,
            'certificate validity until')

    def test_tls_certificate_chain(self):
        self.load('empty')

        self.certificate('root', False)

        subprocess.call(['openssl', 'req', '-new', '-config',
            self.testdir + '/openssl.conf', '-subj', '/CN=int/',
            '-out', self.testdir + '/int.csr',
            '-keyout', self.testdir + '/int.key'])

        subprocess.call(['openssl', 'req', '-new', '-config',
            self.testdir + '/openssl.conf', '-subj', '/CN=end/',
            '-out', self.testdir + '/end.csr',
            '-keyout', self.testdir + '/end.key'])

        with open(self.testdir + '/ca.conf', 'w') as f:
            f.write("""[ ca ]
default_ca = myca

[ myca ]
new_certs_dir = %(dir)s
database = %(database)s
default_md = sha1
policy = myca_policy
serial = %(certserial)s
default_days = 1
x509_extensions = myca_extensions

[ myca_policy ]
commonName = supplied

[ myca_extensions ]
basicConstraints = critical,CA:TRUE""" % {
                'dir': self.testdir,
                'database': self.testdir + '/certindex',
                'certserial': self.testdir + '/certserial'
            })

        with open(self.testdir + '/certserial', 'w') as f:
            f.write('1000')

        with open(self.testdir + '/certindex', 'w') as f:
            f.write('')

        subprocess.call(['openssl', 'ca', '-batch',
            '-config', self.testdir + '/ca.conf',
            '-keyfile', self.testdir + '/root.key',
            '-cert', self.testdir + '/root.crt',
            '-subj', '/CN=int/',
            '-in', self.testdir + '/int.csr',
            '-out', self.testdir + '/int.crt'])

        subprocess.call(['openssl', 'ca', '-batch',
            '-config', self.testdir + '/ca.conf',
            '-keyfile', self.testdir + '/int.key',
            '-cert', self.testdir + '/int.crt',
            '-subj', '/CN=end/',
            '-in', self.testdir + '/end.csr',
            '-out', self.testdir + '/end.crt'])

        with open(self.testdir + '/end-int.crt', 'wb') as crt, \
             open(self.testdir + '/end.crt', 'rb') as end, \
             open(self.testdir + '/int.crt', 'rb') as int:
                crt.write(end.read() + int.read())

        self.context = ssl.create_default_context()
        self.context.check_hostname = False
        self.context.verify_mode = ssl.CERT_REQUIRED
        self.context.load_verify_locations(self.testdir + '/root.crt')

        # incomplete chain

        self.assertIn('success', self.certificate_load('end', 'end'),
            'certificate chain end upload')

        chain = self.conf_get('/certificates/end/chain')
        self.assertEqual(len(chain), 1, 'certificate chain end length')
        self.assertEqual(chain[0]['subject']['common_name'], 'end',
            'certificate chain end subject common name')
        self.assertEqual(chain[0]['issuer']['common_name'], 'int',
            'certificate chain end issuer common name')

        self.add_tls(cert='end')

        try:
            resp = self.get_ssl()
        except ssl.SSLError:
            resp = None

        self.assertEqual(resp, None, 'certificate chain incomplete chain')

        # intermediate

        self.assertIn('success', self.certificate_load('int', 'int'),
            'certificate chain int upload')

        chain = self.conf_get('/certificates/int/chain')
        self.assertEqual(len(chain), 1, 'certificate chain int length')
        self.assertEqual(chain[0]['subject']['common_name'], 'int',
            'certificate chain int subject common name')
        self.assertEqual(chain[0]['issuer']['common_name'], 'root',
            'certificate chain int issuer common name')

        self.add_tls(cert='int')

        self.assertEqual(self.get_ssl()['status'], 200,
            'certificate chain intermediate')

        # intermediate server

        self.assertIn('success', self.certificate_load('end-int', 'end'),
            'certificate chain end-int upload')

        chain = self.conf_get('/certificates/end-int/chain')
        self.assertEqual(len(chain), 2, 'certificate chain end-int length')
        self.assertEqual(chain[0]['subject']['common_name'], 'end',
            'certificate chain end-int int subject common name')
        self.assertEqual(chain[0]['issuer']['common_name'], 'int',
            'certificate chain end-int int issuer common name')
        self.assertEqual(chain[1]['subject']['common_name'], 'int',
            'certificate chain end-int end subject common name')
        self.assertEqual(chain[1]['issuer']['common_name'], 'root',
            'certificate chain end-int end issuer common name')

        self.add_tls(cert='end-int')

        self.assertEqual(self.get_ssl()['status'], 200,
            'certificate chain intermediate server')

    @unittest.expectedFailure
    def test_tls_reconfigure(self):
        self.load('empty')

        self.certificate()

        (resp, sock) = self.get(headers={
            'Host': 'localhost',
            'Connection': 'keep-alive'
        }, start=True)

        self.assertEqual(resp['status'], 200, 'initial status')

        self.add_tls()

        self.assertEqual(self.get(sock=sock)['status'], 200,
            'reconfigure status')
        self.assertEqual(self.get_ssl()['status'], 200,
            'reconfigure tls status')

    def test_tls_keepalive(self):
        self.load('mirror')

        self.certificate()

        self.add_tls(application='mirror')

        (resp, sock) = self.post_ssl(headers={
            'Host': 'localhost',
            'Connection': 'keep-alive',
            'Content-Type': 'text/html'
        }, start=True, body='0123456789')

        self.assertEqual(resp['body'], '0123456789', 'keepalive 1')

        resp = self.post_ssl(headers={
            'Host': 'localhost',
            'Connection': 'close',
            'Content-Type': 'text/html'
        }, sock=sock, body='0123456789')

        self.assertEqual(resp['body'], '0123456789', 'keepalive 2')

    @unittest.expectedFailure
    def test_tls_keepalive_certificate_remove(self):
        self.load('empty')

        self.certificate()

        self.add_tls()

        (resp, sock) = self.get_ssl(headers={
            'Host': 'localhost',
            'Connection': 'keep-alive'
        }, start=True)

        self.conf({
            "application": "empty"
        }, 'listeners/*:7080')
        self.conf_delete('/certificates/default')

        try:
            resp = self.get_ssl(headers={
                'Host': 'localhost',
                'Connection': 'close'
            }, sock=sock)
        except:
            resp = None

        self.assertEqual(resp, None, 'keepalive remove certificate')

    @unittest.expectedFailure
    def test_tls_certificates_remove_all(self):
        self.load('empty')

        self.certificate()

        self.assertIn('success', self.conf_delete('/certificates'),
            'remove all certificates')

    def test_tls_application_respawn(self):
        self.skip_alerts.append(r'process \d+ exited on signal 9')
        self.load('mirror')

        self.certificate()

        self.conf('1', 'applications/mirror/processes')

        self.add_tls(application='mirror')

        (resp, sock) = self.post_ssl(headers={
            'Host': 'localhost',
            'Connection': 'keep-alive',
            'Content-Type': 'text/html'
        }, start=True, body='0123456789')

        app_id = self.findall(r'(\d+)#\d+ "mirror" application started')[0]

        subprocess.call(['kill', '-9', app_id])

        self.wait_for_record(re.compile(' (?!' + app_id +
            '#)(\d+)#\d+ "mirror" application started'))

        resp = self.post_ssl(headers={
            'Host': 'localhost',
            'Connection': 'close',
            'Content-Type': 'text/html'
        }, sock=sock, body='0123456789')

        self.assertEqual(resp['status'], 200, 'application respawn status')
        self.assertEqual(resp['body'], '0123456789', 'application respawn body')

if __name__ == '__main__':
    TestUnitTLS.main()
