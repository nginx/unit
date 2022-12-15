import time

import pytest
from unit.applications.proto import TestApplicationProto


class TestReconfigure(TestApplicationProto):
    prerequisites = {}

    @pytest.fixture(autouse=True)
    def setup_method_fixture(self):
        assert 'success' in self.conf(
            {
                "listeners": {"*:7080": {"pass": "routes"}},
                "routes": [{"action": {"return": 200}}],
                "applications": {},
            }
        )

    def clear_conf(self):
        assert 'success' in self.conf({"listeners": {}, "applications": {}})

    def test_reconfigure(self):
        sock = self.http(
            b"""GET / HTTP/1.1
""",
            raw=True,
            no_recv=True,
        )

        self.clear_conf()

        resp = self.http(
            b"""Host: localhost
Connection: close

""",
            sock=sock,
            raw=True,
        )
        assert resp['status'] == 200, 'finish request'

    def test_reconfigure_2(self):
        sock = self.http(b'', raw=True, no_recv=True)

        # Waiting for connection completion.
        # Delay should be more than TCP_DEFER_ACCEPT.
        time.sleep(1.5)

        self.clear_conf()

        assert self.get(sock=sock)['status'] == 408, 'request timeout'
