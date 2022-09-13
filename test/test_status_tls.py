from unit.applications.tls import TestApplicationTLS
from unit.status import Status


class TestStatusTLS(TestApplicationTLS):
    prerequisites = {'modules': {'openssl': 'any'}}

    def test_status_tls_requests(self):
        self.certificate()

        assert 'success' in self.conf(
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

        assert self.get()['status'] == 200
        assert self.get_ssl(port=7081)['status'] == 200

        assert Status.get('/requests/total') == 2
