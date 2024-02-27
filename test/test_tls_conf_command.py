import ssl

import pytest

from unit.applications.tls import ApplicationTLS

prerequisites = {'modules': {'openssl': 'any'}}

client = ApplicationTLS()


@pytest.fixture(autouse=True)
def setup_method_fixture():
    client.certificate()

    assert 'success' in client.conf(
        {
            "listeners": {
                "*:8080": {
                    "pass": "routes",
                    "tls": {"certificate": "default"},
                }
            },
            "routes": [{"action": {"return": 200}}],
            "applications": {},
        }
    ), 'load application configuration'


def test_tls_conf_command():
    def check_no_connection():
        try:
            client.get_ssl()
            pytest.fail('Unexpected connection.')

        except (ssl.SSLError, ConnectionRefusedError):
            pass

    # Set one conf_commands (disable protocol).

    (_, sock) = client.get_ssl(start=True)

    shared_ciphers = sock.shared_ciphers()

    if not shared_ciphers:
        pytest.skip('no shared ciphers')

    protocols = list(set(c[1] for c in shared_ciphers))
    protocol = sock.cipher()[1]

    if '/' in protocol:
        pytest.skip('Complex protocol format.')

    assert 'success' in client.conf(
        {
            "certificate": "default",
            "conf_commands": {"protocol": f'-{protocol}'},
        },
        'listeners/*:8080/tls',
    ), 'protocol disabled'

    sock.close()

    if len(protocols) > 1:
        (_, sock) = client.get_ssl(start=True)

        cipher = sock.cipher()
        assert cipher[1] != protocol, 'new protocol used'

        shared_ciphers = sock.shared_ciphers()
        ciphers = list(set(c for c in shared_ciphers if c[1] == cipher[1]))

        sock.close()
    else:
        check_no_connection()
        pytest.skip('One TLS protocol available only.')

    # Set two conf_commands (disable protocol and cipher).

    assert 'success' in client.conf(
        {
            "certificate": "default",
            "conf_commands": {
                "protocol": f'-{protocol}',
                "cipherstring": f"{cipher[1]}:!{cipher[0]}",
            },
        },
        'listeners/*:8080/tls',
    ), 'cipher disabled'

    if len(ciphers) > 1:
        (_, sock) = client.get_ssl(start=True)

        cipher_new = sock.cipher()
        assert cipher_new[1] == cipher[1], 'previous protocol used'
        assert cipher_new[0] != cipher[0], 'new cipher used'

        sock.close()

    else:
        check_no_connection()


def test_tls_conf_command_invalid(skip_alert):
    skip_alert(r'SSL_CONF_cmd', r'failed to apply new conf')

    def check_conf_commands(conf_commands):
        assert 'error' in client.conf(
            {"certificate": "default", "conf_commands": conf_commands},
            'listeners/*:8080/tls',
        ), 'ivalid conf_commands'

    check_conf_commands([])
    check_conf_commands("blah")
    check_conf_commands({"": ""})
    check_conf_commands({"blah": ""})
    check_conf_commands({"protocol": {}})
    check_conf_commands({"protocol": "blah"})
    check_conf_commands({"protocol": "TLSv1.2", "blah": ""})
