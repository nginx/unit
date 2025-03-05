import io
import ssl
import subprocess
import time
from pathlib import Path

import pytest

from unit.applications.tls import ApplicationTLS
from unit.option import option

prerequisites = {'modules': {'python': 'any', 'openssl': 'any'}}

client = ApplicationTLS()


def add_tls(application='empty', cert='default', port=8080):
    assert 'success' in client.conf(
        {
            "pass": f"applications/{application}",
            "tls": {"certificate": cert},
        },
        f'listeners/*:{port}',
    )


def ca(cert='root', out='localhost'):
    subprocess.check_output(
        [
            'openssl',
            'ca',
            '-batch',
            '-config',
            f'{option.temp_dir}/ca.conf',
            '-keyfile',
            f'{option.temp_dir}/{cert}.key',
            '-cert',
            f'{option.temp_dir}/{cert}.crt',
            '-in',
            f'{option.temp_dir}/{out}.csr',
            '-out',
            f'{option.temp_dir}/{out}.crt',
        ],
        stderr=subprocess.STDOUT,
    )


def context_cert_req(cert='root'):
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_REQUIRED
    context.verify_flags &= ~ssl.VERIFY_X509_STRICT
    context.load_verify_locations(f'{option.temp_dir}/{cert}.crt')

    return context


def generate_ca_conf():
    Path(f'{option.temp_dir}/ca.conf').write_text(
        f"""[ ca ]
default_ca = myca

[ myca ]
new_certs_dir = {option.temp_dir}
database = {option.temp_dir}/certindex
default_md = sha256
policy = myca_policy
serial = {option.temp_dir}/certserial
default_days = 1
x509_extensions = myca_extensions
copy_extensions = copy

[ myca_policy ]
commonName = optional

[ myca_extensions ]
basicConstraints = critical,CA:TRUE""",
        encoding='utf-8',
    )

    Path(f'{option.temp_dir}/certserial').write_text('1000', encoding='utf-8')
    Path(f'{option.temp_dir}/certindex').touch()
    Path(f'{option.temp_dir}/certindex.attr').touch()


def remove_tls(application='empty', port=8080):
    assert 'success' in client.conf(
        {"pass": f"applications/{application}"}, f'listeners/*:{port}'
    )


def req(name='localhost', subject=None):
    subj = subject if subject is not None else f'/CN={name}/'

    subprocess.check_output(
        [
            'openssl',
            'req',
            '-new',
            '-subj',
            subj,
            '-config',
            f'{option.temp_dir}/openssl.conf',
            '-out',
            f'{option.temp_dir}/{name}.csr',
            '-keyout',
            f'{option.temp_dir}/{name}.key',
        ],
        stderr=subprocess.STDOUT,
    )


def test_tls_listener_option_add():
    client.load('empty')

    client.certificate()

    add_tls()

    assert client.get_ssl()['status'] == 200, 'add listener option'


def test_tls_listener_option_remove():
    client.load('empty')

    client.certificate()

    add_tls()

    client.get_ssl()

    remove_tls()

    assert client.get()['status'] == 200, 'remove listener option'


def test_tls_certificate_remove():
    client.load('empty')

    client.certificate()

    assert 'success' in client.conf_delete(
        '/certificates/default'
    ), 'remove certificate'


def test_tls_certificate_remove_used():
    client.load('empty')

    client.certificate()

    add_tls()

    assert 'error' in client.conf_delete(
        '/certificates/default'
    ), 'remove certificate'


def test_tls_certificate_remove_nonexisting():
    client.load('empty')

    client.certificate()

    add_tls()

    assert 'error' in client.conf_delete(
        '/certificates/blah'
    ), 'remove nonexistings certificate'


@pytest.mark.skip('not yet')
def test_tls_certificate_update():
    client.load('empty')

    client.certificate()

    add_tls()

    cert_old = ssl.get_server_certificate(('127.0.0.1', 8080))

    client.certificate()

    assert cert_old != ssl.get_server_certificate(
        ('127.0.0.1', 8080)
    ), 'update certificate'


@pytest.mark.skip('not yet')
def test_tls_certificate_key_incorrect():
    client.load('empty')

    client.certificate('first', False)
    client.certificate('second', False)

    assert 'error' in client.certificate_load(
        'first', 'second'
    ), 'key incorrect'


def test_tls_certificate_change():
    client.load('empty')

    client.certificate()
    client.certificate('new')

    add_tls()

    cert_old = ssl.get_server_certificate(('127.0.0.1', 8080))

    add_tls(cert='new')

    assert cert_old != ssl.get_server_certificate(
        ('127.0.0.1', 8080)
    ), 'change certificate'


def test_tls_certificate_key_rsa():
    client.load('empty')

    client.certificate()

    assert (
        client.conf_get('/certificates/default/key') == 'RSA (2048 bits)'
    ), 'certificate key rsa'


def test_tls_certificate_key_ec(temp_dir):
    client.load('empty')

    client.openssl_conf()

    subprocess.check_output(
        [
            'openssl',
            'ecparam',
            '-noout',
            '-genkey',
            '-out',
            f'{temp_dir}/ec.key',
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
            f'{temp_dir}/openssl.conf',
            '-key',
            f'{temp_dir}/ec.key',
            '-out',
            f'{temp_dir}/ec.crt',
        ],
        stderr=subprocess.STDOUT,
    )

    client.certificate_load('ec')

    assert (
        client.conf_get('/certificates/ec/key') == 'ECDH'
    ), 'certificate key ec'


def test_tls_certificate_chain_options(date_to_sec_epoch, sec_epoch):
    client.load('empty')
    date_format = '%b %d %X %Y %Z'

    client.certificate()

    chain = client.conf_get('/certificates/default/chain')

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
            sec_epoch
            - date_to_sec_epoch(cert['validity']['since'], date_format)
        )
        < 60
    ), 'certificate validity since'
    assert (
        date_to_sec_epoch(cert['validity']['until'], date_format)
        - date_to_sec_epoch(cert['validity']['since'], date_format)
        == 2592000
    ), 'certificate validity until'


def test_tls_certificate_chain(temp_dir):
    client.load('empty')

    client.certificate('root', False)

    req('int')
    req('end')

    generate_ca_conf()

    ca(cert='root', out='int')
    ca(cert='int', out='end')

    crt_path = f'{temp_dir}/end-int.crt'
    end_path = f'{temp_dir}/end.crt'
    int_path = f'{temp_dir}/int.crt'

    with open(crt_path, 'wb') as crt, open(end_path, 'rb') as end, open(
        int_path, 'rb'
    ) as inter:
        crt.write(end.read() + inter.read())

    # incomplete chain

    assert 'success' in client.certificate_load(
        'end', 'end'
    ), 'certificate chain end upload'

    chain = client.conf_get('/certificates/end/chain')
    assert len(chain) == 1, 'certificate chain end length'
    assert (
        chain[0]['subject']['common_name'] == 'end'
    ), 'certificate chain end subject common name'
    assert (
        chain[0]['issuer']['common_name'] == 'int'
    ), 'certificate chain end issuer common name'

    add_tls(cert='end')

    ctx_cert_req = context_cert_req()
    try:
        resp = client.get_ssl(context=ctx_cert_req)
    except ssl.SSLError:
        resp = None

    assert resp is None, 'certificate chain incomplete chain'

    # intermediate

    assert 'success' in client.certificate_load(
        'int', 'int'
    ), 'certificate chain int upload'

    chain = client.conf_get('/certificates/int/chain')
    assert len(chain) == 1, 'certificate chain int length'
    assert (
        chain[0]['subject']['common_name'] == 'int'
    ), 'certificate chain int subject common name'
    assert (
        chain[0]['issuer']['common_name'] == 'root'
    ), 'certificate chain int issuer common name'

    add_tls(cert='int')

    assert client.get_ssl()['status'] == 200, 'certificate chain intermediate'

    # intermediate server

    assert 'success' in client.certificate_load(
        'end-int', 'end'
    ), 'certificate chain end-int upload'

    chain = client.conf_get('/certificates/end-int/chain')
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

    add_tls(cert='end-int')

    assert (
        client.get_ssl(context=ctx_cert_req)['status'] == 200
    ), 'certificate chain intermediate server'


def test_tls_certificate_chain_long(temp_dir):
    client.load('empty')

    generate_ca_conf()

    # Minimum chain length is 3.
    chain_length = 10

    for i in range(chain_length):
        if i == 0:
            client.certificate('root', False)
        elif i == chain_length - 1:
            req('end')
        else:
            req(f'int{i}')

    for i in range(chain_length - 1):
        if i == 0:
            ca(cert='root', out='int1')
        elif i == chain_length - 2:
            ca(cert=f'int{(chain_length - 2)}', out='end')
        else:
            ca(cert=f'int{i}', out=f'int{(i + 1)}')

    for i in range(chain_length - 1, 0, -1):
        path = (
            f'{temp_dir}/end.crt'
            if i == chain_length - 1
            else f'{temp_dir}/int{i}.crt'
        )

        with open(f'{temp_dir}/all.crt', 'a', encoding='utf-8') as chain, open(
            path, encoding='utf-8'
        ) as cert:
            chain.write(cert.read())

    assert 'success' in client.certificate_load(
        'all', 'end'
    ), 'certificate chain upload'

    chain = client.conf_get('/certificates/all/chain')
    assert len(chain) == chain_length - 1, 'certificate chain length'

    add_tls(cert='all')

    assert (
        client.get_ssl(context=context_cert_req())['status'] == 200
    ), 'certificate chain long'


def test_tls_certificate_empty_cn():
    client.certificate('root', False)

    req(subject='/')

    generate_ca_conf()
    ca()

    assert 'success' in client.certificate_load('localhost', 'localhost')

    cert = client.conf_get('/certificates/localhost')
    assert cert['chain'][0]['subject'] == {}, 'empty subject'
    assert cert['chain'][0]['issuer']['common_name'] == 'root', 'issuer'


def test_tls_certificate_empty_cn_san():
    client.certificate('root', False)

    client.openssl_conf(
        rewrite=True, alt_names=["example.com", "www.example.net"]
    )

    req(subject='/')

    generate_ca_conf()
    ca()

    assert 'success' in client.certificate_load('localhost', 'localhost')

    cert = client.conf_get('/certificates/localhost')
    assert cert['chain'][0]['subject'] == {
        'alt_names': ['example.com', 'www.example.net']
    }, 'subject alt_names'
    assert cert['chain'][0]['issuer']['common_name'] == 'root', 'issuer'


def test_tls_certificate_empty_cn_san_ip():
    client.certificate('root', False)

    client.openssl_conf(
        rewrite=True,
        alt_names=['example.com', 'www.example.net', 'IP|10.0.0.1'],
    )

    req(subject='/')

    generate_ca_conf()
    ca()

    assert 'success' in client.certificate_load('localhost', 'localhost')

    cert = client.conf_get('/certificates/localhost')
    assert cert['chain'][0]['subject'] == {
        'alt_names': ['example.com', 'www.example.net']
    }, 'subject alt_names'
    assert cert['chain'][0]['issuer']['common_name'] == 'root', 'issuer'


def test_tls_keepalive():
    client.load('mirror')

    assert client.get()['status'] == 200, 'init'

    client.certificate()

    add_tls(application='mirror')

    (resp, sock) = client.post_ssl(
        headers={
            'Host': 'localhost',
            'Connection': 'keep-alive',
        },
        start=True,
        body='0123456789',
        read_timeout=1,
    )

    assert resp['body'] == '0123456789', 'keepalive 1'

    resp = client.post_ssl(
        headers={
            'Host': 'localhost',
            'Connection': 'close',
        },
        sock=sock,
        body='0123456789',
    )

    assert resp['body'] == '0123456789', 'keepalive 2'


def test_tls_no_close_notify():
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

    (_, sock) = client.get_ssl(start=True)

    time.sleep(5)

    sock.close()


@pytest.mark.skip('not yet')
def test_tls_keepalive_certificate_remove():
    client.load('empty')

    assert client.get()['status'] == 200, 'init'

    client.certificate()

    add_tls()

    (resp, sock) = client.get_ssl(
        headers={'Host': 'localhost', 'Connection': 'keep-alive'},
        start=True,
        read_timeout=1,
    )

    assert 'success' in client.conf(
        {"pass": "applications/empty"}, 'listeners/*:8080'
    )
    assert 'success' in client.conf_delete('/certificates/default')

    try:
        resp = client.get_ssl(sock=sock)

    except KeyboardInterrupt:
        raise

    except:
        resp = None

    assert resp is None, 'keepalive remove certificate'


@pytest.mark.skip('not yet')
def test_tls_certificates_remove_all():
    client.load('empty')

    client.certificate()

    assert 'success' in client.conf_delete(
        '/certificates'
    ), 'remove all certificates'


def test_tls_application_respawn(findall, skip_alert, wait_for_record):
    client.load('mirror')

    client.certificate()

    assert 'success' in client.conf('1', 'applications/mirror/processes')

    add_tls(application='mirror')

    (_, sock) = client.post_ssl(
        headers={
            'Host': 'localhost',
            'Connection': 'keep-alive',
        },
        start=True,
        body='0123456789',
        read_timeout=1,
    )

    app_id = findall(r'(\d+)#\d+ "mirror" application started')[0]

    subprocess.check_output(['kill', '-9', app_id])

    skip_alert(fr'process {app_id} exited on signal 9')

    wait_for_record(fr' (?!{app_id}#)(\d+)#\d+ "mirror" application started')

    resp = client.post_ssl(sock=sock, body='0123456789')

    assert resp['status'] == 200, 'application respawn status'
    assert resp['body'] == '0123456789', 'application respawn body'


def test_tls_url_scheme():
    client.load('variables')

    assert (
        client.post(
            headers={
                'Host': 'localhost',
                'Content-Type': 'text/html',
                'Custom-Header': '',
                'Connection': 'close',
            }
        )['headers']['Wsgi-Url-Scheme']
        == 'http'
    ), 'url scheme http'

    client.certificate()

    add_tls(application='variables')

    assert (
        client.post_ssl(
            headers={
                'Host': 'localhost',
                'Content-Type': 'text/html',
                'Custom-Header': '',
                'Connection': 'close',
            }
        )['headers']['Wsgi-Url-Scheme']
        == 'https'
    ), 'url scheme https'


def test_tls_big_upload():
    client.load('upload')

    client.certificate()

    add_tls(application='upload')

    filename = 'test.txt'
    data = '0123456789' * 9000

    res = client.post_ssl(
        body={
            'file': {
                'filename': filename,
                'type': 'text/plain',
                'data': io.StringIO(data),
            }
        }
    )
    assert res['status'] == 200, 'status ok'
    assert res['body'] == f'{filename}{data}'


def test_tls_multi_listener():
    client.load('empty')

    client.certificate()

    add_tls()
    add_tls(port=8081)

    assert client.get_ssl()['status'] == 200, 'listener #1'

    assert client.get_ssl(port=8081)['status'] == 200, 'listener #2'
