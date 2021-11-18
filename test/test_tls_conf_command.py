import ssl

import pytest
from unit.applications.tls import TestApplicationTLS


class TestTLSConfCommand(TestApplicationTLS):
    prerequisites = {'modules': {'openssl': 'any'}}

    @pytest.fixture(autouse=True)
    def setup_method_fixture(self, request):
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

    def test_tls_conf_command(self):
        def check_no_connection():
            try:
                self.get_ssl()
                pytest.fail('Unexpected connection.')

            except (ssl.SSLError, ConnectionRefusedError):
                pass

        # Set one conf_commands (disable protocol).

        (resp, sock) = self.get_ssl(start=True)

        shared_ciphers = sock.shared_ciphers()
        protocols = list(set(c[1] for c in shared_ciphers))
        protocol = sock.cipher()[1]

        if '/' in protocol:
            pytest.skip('Complex protocol format.')

        assert 'success' in self.conf(
            {
                "certificate": "default",
                "conf_commands": {"protocol": '-' + protocol},
            },
            'listeners/*:7080/tls',
        ), 'protocol disabled'

        sock.close()

        if len(protocols) > 1:
            (resp, sock) = self.get_ssl(start=True)

            cipher = sock.cipher()
            assert cipher[1] != protocol, 'new protocol used'

            shared_ciphers = sock.shared_ciphers()
            ciphers = list(set(c for c in shared_ciphers if c[1] == cipher[1]))

            sock.close()
        else:
            check_no_connection()
            pytest.skip('One TLS protocol available only.')

        # Set two conf_commands (disable protocol and cipher).

        assert 'success' in self.conf(
            {
                "certificate": "default",
                "conf_commands": {
                    "protocol": '-' + protocol,
                    "cipherstring": cipher[1] + ":!" + cipher[0],
                },
            },
            'listeners/*:7080/tls',
        ), 'cipher disabled'

        if len(ciphers) > 1:
            (resp, sock) = self.get_ssl(start=True)

            cipher_new = sock.cipher()
            assert cipher_new[1] == cipher[1], 'previous protocol used'
            assert cipher_new[0] != cipher[0], 'new cipher used'

            sock.close()

        else:
            check_no_connection()

    def test_tls_conf_command_invalid(self, skip_alert):
        skip_alert(r'SSL_CONF_cmd', r'failed to apply new conf')

        def check_conf_commands(conf_commands):
            assert 'error' in self.conf(
                {"certificate": "default", "conf_commands": conf_commands},
                'listeners/*:7080/tls',
            ), 'ivalid conf_commands'

        check_conf_commands([])
        check_conf_commands("blah")
        check_conf_commands({"": ""})
        check_conf_commands({"blah": ""})
        check_conf_commands({"protocol": {}})
        check_conf_commands({"protocol": "blah"})
        check_conf_commands({"protocol": "TLSv1.2", "blah": ""})
