import re

import pytest

from unit.applications.proto import ApplicationProto

client = ApplicationProto()


@pytest.fixture(autouse=True)
def setup_method_fixture():
    assert 'success' in client.conf(
        {
            "listeners": {"*:8080": {"pass": "routes"}},
            "routes": [{"action": {"return": 200}}],
            "applications": {},
        }
    )


def get_resps_sc(req=10):
    to_send = b"""GET / HTTP/1.1
Host: localhost

""" * (
        req - 1
    )

    to_send += b"""GET / HTTP/1.1
Host: localhost
Connection: close

"""

    return client.http(to_send, raw_resp=True, raw=True)


def test_return():
    resp = client.get()
    assert resp['status'] == 200
    assert 'Server' in resp['headers']
    assert 'Date' in resp['headers']
    assert resp['headers']['Content-Length'] == '0'
    assert resp['headers']['Connection'] == 'close'
    assert resp['body'] == '', 'body'

    resp = client.post(body='blah')
    assert resp['status'] == 200
    assert resp['body'] == '', 'body'

    resp = get_resps_sc()
    assert len(re.findall('200 OK', resp)) == 10
    assert len(re.findall('Connection:', resp)) == 1
    assert len(re.findall('Connection: close', resp)) == 1

    resp = client.get(http_10=True)
    assert resp['status'] == 200
    assert 'Server' in resp['headers']
    assert 'Date' in resp['headers']
    assert resp['headers']['Content-Length'] == '0'
    assert 'Connection' not in resp['headers']
    assert resp['body'] == '', 'body'


def test_return_update():
    assert 'success' in client.conf('0', 'routes/0/action/return')

    resp = client.get()
    assert resp['status'] == 0
    assert resp['body'] == ''

    assert 'success' in client.conf('404', 'routes/0/action/return')

    resp = client.get()
    assert resp['status'] == 404
    assert resp['body'] != ''

    assert 'success' in client.conf('598', 'routes/0/action/return')

    resp = client.get()
    assert resp['status'] == 598
    assert resp['body'] != ''

    assert 'success' in client.conf('999', 'routes/0/action/return')

    resp = client.get()
    assert resp['status'] == 999
    assert resp['body'] == ''


def test_return_location():
    reserved = ":/?#[]@!&'()*+,;="
    unreserved = (
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
    )
    unsafe = " \"%<>\\^`{|}"
    unsafe_enc = "%20%22%25%3C%3E%5C%5E%60%7B%7C%7D"

    def check_location(location, expect=None):
        if expect is None:
            expect = location

        assert 'success' in client.conf(
            {"return": 301, "location": location}, 'routes/0/action'
        ), 'configure location'

        assert client.get()['headers']['Location'] == expect

    # FAIL: can't specify empty header value.
    # check_location("")

    check_location(reserved)

    # After first "?" all other "?" encoded.
    check_location(f'/?{reserved}', "/?:/%3F#[]@!&'()*+,;=")
    check_location("???", "?%3F%3F")

    # After first "#" all other "?" or "#" encoded.
    check_location(f'/#{reserved}', "/#:/%3F%23[]@!&'()*+,;=")
    check_location("##?#?", "#%23%3F%23%3F")

    # After first "?" next "#" not encoded.
    check_location(f'/?#{reserved}', "/?#:/%3F%23[]@!&'()*+,;=")
    check_location("??##", "?%3F#%23")
    check_location("/?##?", "/?#%23%3F")

    # Unreserved never encoded.
    check_location(unreserved)
    check_location(f'/{unreserved}?{unreserved}#{unreserved}')

    # Unsafe always encoded.
    check_location(unsafe, unsafe_enc)
    check_location(f'?{unsafe}', f'?{unsafe_enc}')
    check_location(f'#{unsafe}', f'#{unsafe_enc}')

    # %00-%20 and %7F-%FF always encoded.
    check_location("\u0000\u0018\u001F\u0020\u0021", "%00%18%1F%20!")
    check_location("\u007F\u0080н\u20BD", "%7F%C2%80%D0%BD%E2%82%BD")

    # Encoded string detection.  If at least one char need to be encoded
    # then whole string will be encoded.
    check_location("%20")
    check_location("/%20?%20#%20")
    check_location(" %20", "%20%2520")
    check_location("%20 ", "%2520%20")
    check_location("/%20?%20#%20 ", "/%2520?%2520#%2520%20")


def test_return_location_edit():
    assert 'success' in client.conf(
        {"return": 302, "location": "blah"}, 'routes/0/action'
    ), 'configure init location'
    assert client.get()['headers']['Location'] == 'blah'

    assert 'success' in client.conf_delete(
        'routes/0/action/location'
    ), 'location delete'
    assert 'Location' not in client.get()['headers']

    assert 'success' in client.conf(
        '"blah"', 'routes/0/action/location'
    ), 'location restore'
    assert client.get()['headers']['Location'] == 'blah'

    assert 'error' in client.conf_post(
        '"blah"', 'routes/0/action/location'
    ), 'location method not allowed'
    assert client.get()['headers']['Location'] == 'blah'

    assert 'success' in client.conf(
        '"https://${host}${uri}"', 'routes/0/action/location'
    ), 'location with variables'
    assert client.get()['headers']['Location'] == 'https://localhost/'

    assert 'success' in client.conf(
        '"/#$host"', 'routes/0/action/location'
    ), 'location with encoding and a variable'
    assert client.get()['headers']['Location'] == '/#localhost'

    assert (
        client.get(headers={"Host": "#foo?bar", "Connection": "close"})[
            'headers'
        ]['Location']
        == "/#%23foo%3Fbar"
    ), 'location with a variable with encoding'

    assert 'success' in client.conf(
        '""', 'routes/0/action/location'
    ), 'location empty'
    assert client.get()['headers']['Location'] == ''

    assert 'success' in client.conf(
        '"${host}"', 'routes/0/action/location'
    ), 'location empty with variable'
    assert (
        client.get(headers={"Host": "", "Connection": "close"})['headers'][
            'Location'
        ]
        == ""
    ), 'location with empty variable'


def test_return_invalid():
    def check_error(conf):
        assert 'error' in client.conf(conf, 'routes/0/action')

    check_error({"return": "200"})
    check_error({"return": []})
    check_error({"return": 80.1})
    check_error({"return": 1000})
    check_error({"return": -1})
    check_error({"return": 200, "share": "/blah"})
    check_error({"return": 200, "location": "$hos"})
    check_error({"return": 200, "location": "$hostblah"})

    assert 'error' in client.conf(
        '001', 'routes/0/action/return'
    ), 'leading zero'

    check_error({"return": 301, "location": 0})
    check_error({"return": 301, "location": []})
