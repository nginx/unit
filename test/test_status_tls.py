from unit.applications.tls import ApplicationTLS
from unit.status import Status

prerequisites = {'modules': {'openssl': 'any'}}

client = ApplicationTLS()


def test_status_tls_requests():
    client.certificate()

    assert 'success' in client.conf(
        {
            "listeners": {
                "*:7080": {"pass": "routes"},
                "*:7081": {
                    "pass": "routes",
                    "tls": {"certificate": "default"},
                },
            },
            "routes": [{"action": {"return": 200}}],
            "applications": {},
        }
    )

    Status.init()

    assert client.get()['status'] == 200
    assert client.get_ssl(port=7081)['status'] == 200

    assert Status.get('/requests/total') == 2
