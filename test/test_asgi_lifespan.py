import os

from conftest import unit_stop
from packaging import version
from unit.applications.lang.python import TestApplicationPython
from unit.option import option


class TestASGILifespan(TestApplicationPython):
    prerequisites = {
        'modules': {
            'python': lambda v: version.parse(v) >= version.parse('3.5')
        }
    }
    load_module = 'asgi'

    def setup_cookies(self, prefix):
        base_dir = option.test_dir + '/python/lifespan/empty'

        os.chmod(base_dir, 0o777)

        for name in ['startup', 'shutdown', 'version']:
            path = option.test_dir + '/python/lifespan/empty/' + prefix + name
            open(path, 'a').close()
            os.chmod(path, 0o777)

    def assert_cookies(self, prefix):
        for name in ['startup', 'shutdown']:
            path = option.test_dir + '/python/lifespan/empty/' + prefix + name
            exists = os.path.isfile(path)
            if exists:
                os.remove(path)

            assert not exists, name

        path = option.test_dir + '/python/lifespan/empty/' + prefix + 'version'

        with open(path, 'r') as f:
            version = f.read()

        os.remove(path)

        assert version == '3.0 2.0', 'version'

    def test_asgi_lifespan(self):
        self.load('lifespan/empty')

        self.setup_cookies('')

        assert self.get()['status'] == 204

        unit_stop()

        self.assert_cookies('')

    def test_asgi_lifespan_targets(self):
        assert 'success' in self.conf(
            {
                "listeners": {"*:7080": {"pass": "routes"}},
                "routes": [
                    {
                        "match": {"uri": "/1"},
                        "action": {"pass": "applications/targets/1"},
                    },
                    {
                        "match": {"uri": "/2"},
                        "action": {"pass": "applications/targets/2"},
                    },
                ],
                "applications": {
                    "targets": {
                        "type": self.get_application_type(),
                        "processes": {"spare": 0},
                        "working_directory": option.test_dir
                        + "/python/lifespan/empty",
                        "path": option.test_dir + '/python/lifespan/empty',
                        "targets": {
                            "1": {"module": "asgi", "callable": "application"},
                            "2": {
                                "module": "asgi",
                                "callable": "application2",
                            },
                        },
                    }
                },
            }
        )

        self.setup_cookies('')
        self.setup_cookies('app2_')

        assert self.get(url="/1")['status'] == 204
        assert self.get(url="/2")['status'] == 204

        unit_stop()

        self.assert_cookies('')
        self.assert_cookies('app2_')

    def test_asgi_lifespan_failed(self):
        self.load('lifespan/failed')

        assert self.get()['status'] == 503

        assert (
            self.wait_for_record(r'\[error\].*Application startup failed')
            is not None
        ), 'error message'
        assert self.wait_for_record(r'Exception blah') is not None, 'exception'

    def test_asgi_lifespan_error(self):
        self.load('lifespan/error')

        self.get()

        assert self.wait_for_record(r'Exception blah') is not None, 'exception'

    def test_asgi_lifespan_error_auto(self):
        self.load('lifespan/error_auto')

        self.get()

        assert self.wait_for_record(r'AssertionError') is not None, 'assertion'
