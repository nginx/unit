import re

import pytest
from unit.applications.lang.python import ApplicationPython

prerequisites = {'modules': {'python': 'any'}}

client = ApplicationPython()


@pytest.fixture(autouse=True)
def setup_method_fixture():
    client.load('mirror')

    assert 'success' in client.conf(
        {"http": {"chunked_transform": True}}, 'settings'
    )


def test_chunked():
    def chunks(chunks=[]):
        body = ''

        for c in chunks:
            body = f'{body}{len(c):x}\r\n{c}\r\n'

        resp = client.get(
            headers={
                'Host': 'localhost',
                'Connection': 'close',
                'Transfer-Encoding': 'chunked',
            },
            body=f'{body}0\r\n\r\n',
        )

        expect_body = ''.join(chunks)

        assert resp['status'] == 200
        assert resp['headers']['Content-Length'] == str(len(expect_body))
        assert resp['body'] == expect_body

    chunks()
    chunks(['1'])
    chunks(['0123456789'])
    chunks(['0123456789' * 128])
    chunks(['0123456789' * 512])
    chunks(['0123456789' * 128, '1', '1', '0123456789' * 128, '1'])


def test_chunked_pipeline():
    sock = client.get(
        no_recv=True,
        headers={
            'Host': 'localhost',
            'Transfer-Encoding': 'chunked',
        },
        body='1\r\n$\r\n0\r\n\r\n',
    )

    resp = client.get(
        sock=sock,
        headers={
            'Host': 'localhost',
            'Transfer-Encoding': 'chunked',
            'Connection': 'close',
        },
        body='1\r\n%\r\n0\r\n\r\n',
        raw_resp=True,
    )

    assert len(re.findall('200 OK', resp)) == 2
    assert len(re.findall('Content-Length: 1', resp)) == 2
    assert len(re.findall('$', resp)) == 1
    assert len(re.findall('%', resp)) == 1


def test_chunked_max_body_size():
    assert 'success' in client.conf(
        {'max_body_size': 1024, 'chunked_transform': True}, 'settings/http'
    )

    body = f'{2048:x}\r\n{"x" * 2048}\r\n0\r\n\r\n'

    assert (
        client.get(
            headers={
                'Host': 'localhost',
                'Connection': 'close',
                'Transfer-Encoding': 'chunked',
            },
            body=body,
        )['status']
        == 413
    )


def test_chunked_after_last():
    resp = client.get(
        headers={
            'Host': 'localhost',
            'Connection': 'close',
            'Transfer-Encoding': 'chunked',
        },
        body='1\r\na\r\n0\r\n\r\n1\r\nb\r\n0\r\n\r\n',
    )

    assert resp['status'] == 200
    assert resp['headers']['Content-Length'] == '1'
    assert resp['body'] == 'a'


def test_chunked_transform():
    assert 'success' in client.conf(
        {"http": {"chunked_transform": False}}, 'settings'
    )

    assert (
        client.get(
            headers={
                'Host': 'localhost',
                'Connection': 'close',
                'Transfer-Encoding': 'chunked',
            },
            body='0\r\n\r\n',
        )['status']
        == 411
    )


def test_chunked_invalid():
    # invalid chunkes

    def check_body(body):
        assert (
            client.get(
                headers={
                    'Host': 'localhost',
                    'Connection': 'close',
                    'Transfer-Encoding': 'chunked',
                },
                body=body,
            )['status']
            == 400
        )

    check_body('1\r\nblah\r\n0\r\n\r\n')
    check_body('1\r\n\r\n1\r\n0\r\n\r\n')
    check_body('1\r\n1\r\n\r\n0\r\n\r\n')

    # invalid transfer encoding header

    assert (
        client.get(
            headers={
                'Host': 'localhost',
                'Connection': 'close',
                'Transfer-Encoding': ['chunked', 'chunked'],
            },
            body='0\r\n\r\n',
        )['status']
        == 400
    ), 'two Transfer-Encoding headers'

    assert (
        client.get(
            headers={
                'Host': 'localhost',
                'Connection': 'close',
                'Transfer-Encoding': 'chunked',
                'Content-Length': '5',
            },
            body='0\r\n\r\n',
        )['status']
        == 400
    ), 'Transfer-Encoding and Content-Length'

    assert (
        client.get(
            http_10=True,
            headers={
                'Host': 'localhost',
                'Connection': 'close',
                'Transfer-Encoding': 'chunked',
            },
            body='0\r\n\r\n',
        )['status']
        == 400
    ), 'Transfer-Encoding HTTP/1.0'
