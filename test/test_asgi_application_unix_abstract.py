from packaging import version
from unit.applications.lang.python import TestApplicationPython


class TestASGIApplicationUnixAbstract(TestApplicationPython):
    prerequisites = {
        'modules': {
            'python': lambda v: version.parse(v) >= version.parse('3.5')
        },
        'features': ['unix_abstract'],
    }
    load_module = 'asgi'

    def test_asgi_application_unix_abstract(self):
        self.load('empty')

        addr = '\0sock'
        assert 'success' in self.conf(
            {"unix:@" + addr[1:]: {"pass": "applications/empty"}},
            'listeners',
        )

        assert self.get(sock_type='unix', addr=addr)['status'] == 200
