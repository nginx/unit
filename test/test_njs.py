import os

from unit.applications.proto import TestApplicationProto
from unit.option import option
from unit.utils import waitforfiles


class TestNJS(TestApplicationProto):
    prerequisites = {'modules': {'njs': 'any'}}

    def setup_method(self):
        assert 'success' in self.conf(
            {
                "listeners": {"*:7080": {"pass": "routes"}},
                "routes": [
                    {"action": {"share": option.temp_dir + "/assets$uri"}}
                ],
            }
        )

    def create_files(self, *files):
        assets_dir = option.temp_dir + '/assets/'
        os.makedirs(assets_dir)

        [open(assets_dir + f, 'a') for f in files]
        waitforfiles(*[assets_dir + f for f in files])

    def set_share(self, share):
        assert 'success' in self.conf(share, 'routes/0/action/share')

    def check_expression(self, expression, url='/'):
        self.set_share('"`' + option.temp_dir + '/assets' + expression + '`"')
        assert self.get(url=url)['status'] == 200

    def test_njs_template_string(self, temp_dir):
        self.create_files('str', '`string`', '`backtick', 'l1\nl2')

        self.check_expression('/str')
        self.check_expression('/\\\\`backtick')
        self.check_expression('/l1\\nl2')

        self.set_share('"' + temp_dir + '/assets/`string`"')
        assert self.get()['status'] == 200

    def test_njs_template_expression(self, temp_dir):
        self.create_files('str', 'localhost')

        self.check_expression('${uri}', '/str')
        self.check_expression('${uri}${host}')
        self.check_expression('${uri + host}')
        self.check_expression('${uri + `${host}`}')

    def test_njs_iteration(self, temp_dir):
        self.create_files('Connection,Host', 'close,localhost')

        self.check_expression('/${Object.keys(headers).sort().join()}')
        self.check_expression('/${Object.values(headers).sort().join()}')

    def test_njs_variables(self, temp_dir):
        self.create_files('str', 'localhost', '127.0.0.1')

        self.check_expression('/${host}')
        self.check_expression('/${remoteAddr}')
        self.check_expression('/${headers.Host}')

        self.set_share('"`' + temp_dir + '/assets/${cookies.foo}`"')
        assert (
            self.get(headers={'Cookie': 'foo=str', 'Connection': 'close'})[
                'status'
            ]
            == 200
        ), 'cookies'

        self.set_share('"`' + temp_dir + '/assets/${args.foo}`"')
        assert self.get(url='/?foo=str')['status'] == 200, 'args'

    def test_njs_invalid(self, temp_dir, skip_alert):
        skip_alert(r'js exception:')

        def check_invalid(template):
            assert 'error' in self.conf(template, 'routes/0/action/share')

        check_invalid('"`a"')
        check_invalid('"`a``"')
        check_invalid('"`a`/"')

        def check_invalid_resolve(template):
            assert 'success' in self.conf(template, 'routes/0/action/share')
            assert self.get()['status'] == 500

        check_invalid_resolve('"`${a}`"')
        check_invalid_resolve('"`${uri.a.a}`"')
