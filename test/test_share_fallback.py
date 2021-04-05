import os

import pytest

from unit.applications.proto import TestApplicationProto
from unit.option import option


class TestStatic(TestApplicationProto):
    prerequisites = {}

    def setup_method(self):
        os.makedirs(option.temp_dir + '/assets/dir')
        with open(option.temp_dir + '/assets/index.html', 'w') as index:
            index.write('0123456789')

        os.makedirs(option.temp_dir + '/assets/403')
        os.chmod(option.temp_dir + '/assets/403', 0o000)

        self._load_conf(
            {
                "listeners": {
                    "*:7080": {"pass": "routes"},
                    "*:7081": {"pass": "routes"},
                },
                "routes": [{"action": {"share": option.temp_dir + "/assets"}}],
                "applications": {},
            }
        )

    def teardown_method(self):
        try:
            os.chmod(option.temp_dir + '/assets/403', 0o777)
        except FileNotFoundError:
            pass

    def action_update(self, conf):
        assert 'success' in self.conf(conf, 'routes/0/action')

    def test_fallback(self):
        self.action_update({"share": "/blah"})
        assert self.get()['status'] == 404, 'bad path no fallback'

        self.action_update({"share": "/blah", "fallback": {"return": 200}})

        resp = self.get()
        assert resp['status'] == 200, 'bad path fallback status'
        assert resp['body'] == '', 'bad path fallback'

    def test_fallback_valid_path(self, temp_dir):
        self.action_update(
            {"share": temp_dir + "/assets", "fallback": {"return": 200}}
        )
        resp = self.get()
        assert resp['status'] == 200, 'fallback status'
        assert resp['body'] == '0123456789', 'fallback'

        resp = self.get(url='/403/')
        assert resp['status'] == 200, 'fallback status 403'
        assert resp['body'] == '', 'fallback 403'

        resp = self.post()
        assert resp['status'] == 200, 'fallback status 405'
        assert resp['body'] == '', 'fallback 405'

        assert self.get(url='/dir')['status'] == 301, 'fallback status 301'

    def test_fallback_nested(self):
        self.action_update(
            {
                "share": "/blah",
                "fallback": {
                    "share": "/blah/blah",
                    "fallback": {"return": 200},
                },
            }
        )

        resp = self.get()
        assert resp['status'] == 200, 'fallback nested status'
        assert resp['body'] == '', 'fallback nested'

    def test_fallback_share(self, temp_dir):
        self.action_update(
            {"share": "/blah", "fallback": {"share": temp_dir + "/assets"},}
        )

        resp = self.get()
        assert resp['status'] == 200, 'fallback share status'
        assert resp['body'] == '0123456789', 'fallback share'

        resp = self.head()
        assert resp['status'] == 200, 'fallback share status HEAD'
        assert resp['body'] == '', 'fallback share HEAD'

        assert (
            self.get(url='/dir')['status'] == 301
        ), 'fallback share status 301'

    def test_fallback_proxy(self):
        assert 'success' in self.conf(
            [
                {
                    "match": {"destination": "*:7081"},
                    "action": {"return": 200},
                },
                {
                    "action": {
                        "share": "/blah",
                        "fallback": {"proxy": "http://127.0.0.1:7081"},
                    }
                },
            ],
            'routes',
        ), 'configure fallback proxy route'

        resp = self.get()
        assert resp['status'] == 200, 'fallback proxy status'
        assert resp['body'] == '', 'fallback proxy'

    @pytest.mark.skip('not yet')
    def test_fallback_proxy_loop(self, skip_alert):
        skip_alert(
            r'open.*/blah/index.html.*failed',
            r'accept.*failed',
            r'socket.*failed',
            r'new connections are not accepted',
        )

        self.action_update(
            {"share": "/blah", "fallback": {"proxy": "http://127.0.0.1:7080"}}
        )
        self.get(no_recv=True)

        assert 'success' in self.conf_delete('listeners/*:7081')
        self.get(read_timeout=1)

    def test_fallback_invalid(self):
        def check_error(conf):
            assert 'error' in self.conf(conf, 'routes/0/action')

        check_error({"share": "/blah", "fallback": {}})
        check_error({"share": "/blah", "fallback": ""})
        check_error({"return": 200, "fallback": {"share": "/blah"}})
        check_error(
            {"proxy": "http://127.0.0.1:7081", "fallback": {"share": "/blah"}}
        )
        check_error({"fallback": {"share": "/blah"}})
