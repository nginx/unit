from unit.applications.tls import ApplicationTLS
from unit.status import Status

prerequisites = {'modules': {'openssl': 'any'}}

client = ApplicationTLS()


def test_status_tls_requests():
    client.certificate()

    assert 'success' in client.conf(
        {
            "listeners": {
                "*:8080": {"pass": "routes"},
                "*:8081": {
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
    assert client.get_ssl(port=8081)['status'] == 200

    assert Status.get('/requests/total') == 2
