from unit.applications.tls import ApplicationTLS

prerequisites = {'modules': {'openssl': 'any'}}

client = ApplicationTLS()


def test_routes_match_scheme_tls():
    client.certificate()

    assert 'success' in client.conf(
        {
            "listeners": {
                "*:8080": {"pass": "routes"},
                "*:8081": {
                    "pass": "routes",
                    "tls": {"certificate": 'default'},
                },
            },
            "routes": [
                {"match": {"scheme": "http"}, "action": {"return": 200}},
                {"match": {"scheme": "https"}, "action": {"return": 201}},
            ],
            "applications": {},
        }
    ), 'scheme configure'

    assert client.get()['status'] == 200, 'http'
    assert client.get_ssl(port=8081)['status'] == 201, 'https'
