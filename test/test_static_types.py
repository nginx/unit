from pathlib import Path

import pytest
from unit.applications.proto import TestApplicationProto


class TestStaticTypes(TestApplicationProto):
    prerequisites = {}

    @pytest.fixture(autouse=True)
    def setup_method_fixture(self, temp_dir):
        Path(temp_dir + '/assets').mkdir()
        for ext in ['.xml', '.mp4', '.php', '', '.txt', '.html', '.png']:
            Path(temp_dir + '/assets/file' + ext).write_text(ext)

        Path(temp_dir + '/assets/index.html').write_text('index')

        self._load_conf(
            {
                "listeners": {
                    "*:7080": {"pass": "routes"},
                    "*:7081": {"pass": "routes"},
                },
                "routes": [{"action": {"share": temp_dir + "/assets$uri"}}],
                "applications": {},
            }
        )

    def action_update(self, conf):
        assert 'success' in self.conf(conf, 'routes/0/action')

    def check_body(self, http_url, body):
        resp = self.get(url=http_url)
        assert resp['status'] == 200, 'status'
        assert resp['body'] == body, 'body'

    def test_static_types_basic(self, temp_dir):
        self.action_update({"share": temp_dir + "/assets$uri"})
        self.check_body('/index.html', 'index')
        self.check_body('/file.xml', '.xml')

        self.action_update(
            {"share": temp_dir + "/assets$uri", "types": "application/xml"}
        )
        self.check_body('/file.xml', '.xml')

        self.action_update(
            {"share": temp_dir + "/assets$uri", "types": ["application/xml"]}
        )
        self.check_body('/file.xml', '.xml')

        self.action_update({"share": temp_dir + "/assets$uri", "types": [""]})
        assert self.get(url='/file.xml')['status'] == 403, 'no mtype'

    def test_static_types_wildcard(self, temp_dir):
        self.action_update(
            {"share": temp_dir + "/assets$uri", "types": ["application/*"]}
        )
        self.check_body('/file.xml', '.xml')
        assert self.get(url='/file.mp4')['status'] == 403, 'app * mtype mp4'

        self.action_update(
            {"share": temp_dir + "/assets$uri", "types": ["video/*"]}
        )
        assert self.get(url='/file.xml')['status'] == 403, 'video * mtype xml'
        self.check_body('/file.mp4', '.mp4')

    def test_static_types_negation(self, temp_dir):
        self.action_update(
            {"share": temp_dir + "/assets$uri", "types": ["!application/xml"]}
        )
        assert self.get(url='/file.xml')['status'] == 403, 'forbidden negation'
        self.check_body('/file.mp4', '.mp4')

        # sorting negation
        self.action_update(
            {
                "share": temp_dir + "/assets$uri",
                "types": ["!video/*", "image/png", "!image/jpg"],
            }
        )
        assert self.get(url='/file.mp4')['status'] == 403, 'negation sort mp4'
        self.check_body('/file.png', '.png')
        assert self.get(url='/file.jpg')['status'] == 403, 'negation sort jpg'

    def test_static_types_regex(self, temp_dir):
        self.action_update(
            {
                "share": temp_dir + "/assets$uri",
                "types": ["~text/(html|plain)"],
            }
        )
        assert self.get(url='/file.php')['status'] == 403, 'regex fail'
        self.check_body('/file.html', '.html')
        self.check_body('/file.txt', '.txt')

    def test_static_types_case(self, temp_dir):
        self.action_update(
            {"share": temp_dir + "/assets$uri", "types": ["!APpliCaTiOn/xMl"]}
        )
        self.check_body('/file.mp4', '.mp4')
        assert (
            self.get(url='/file.xml')['status'] == 403
        ), 'mixed case xml negation'

        self.action_update(
            {"share": temp_dir + "/assets$uri", "types": ["vIdEo/mp4"]}
        )
        assert self.get(url='/file.mp4')['status'] == 200, 'mixed case'
        assert (
            self.get(url='/file.xml')['status'] == 403
        ), 'mixed case video negation'

        self.action_update(
            {"share": temp_dir + "/assets$uri", "types": ["vIdEo/*"]}
        )
        self.check_body('/file.mp4', '.mp4')
        assert (
            self.get(url='/file.xml')['status'] == 403
        ), 'mixed case video * negation'

    def test_static_types_fallback(self, temp_dir):
        assert 'success' in self.conf(
            [
                {
                    "match": {"destination": "*:7081"},
                    "action": {"return": 200},
                },
                {
                    "action": {
                        "share": temp_dir + "/assets$uri",
                        "types": ["!application/x-httpd-php"],
                        "fallback": {"proxy": "http://127.0.0.1:7081"},
                    }
                },
            ],
            'routes',
        ), 'configure fallback proxy route'

        self.check_body('/file.php', '')
        self.check_body('/file.mp4', '.mp4')

    def test_static_types_index(self, temp_dir):
        self.action_update(
            {"share": temp_dir + "/assets$uri", "types": "application/xml"}
        )
        self.check_body('/', 'index')
        self.check_body('/file.xml', '.xml')
        assert self.get(url='/index.html')['status'] == 403, 'forbidden mtype'
        assert self.get(url='/file.mp4')['status'] == 403, 'forbidden mtype'

    def test_static_types_custom_mime(self, temp_dir):
        self._load_conf(
            {
                "listeners": {"*:7080": {"pass": "routes"}},
                "routes": [{"action": {"share": temp_dir + "/assets$uri"}}],
                "applications": {},
                "settings": {
                    "http": {
                        "static": {"mime_types": {"test/mime-type": ["file"]}}
                    }
                },
            }
        )

        self.action_update({"share": temp_dir + "/assets$uri", "types": [""]})
        assert self.get(url='/file')['status'] == 403, 'forbidden custom mime'

        self.action_update(
            {"share": temp_dir + "/assets$uri", "types": ["test/mime-type"]}
        )
        self.check_body('/file', '')
