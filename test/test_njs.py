import os

from unit.applications.proto import TestApplicationProto
from unit.option import option


class TestNJS(TestApplicationProto):
    prerequisites = {'modules': {'njs': 'any'}}

    def setup_method(self):
        os.makedirs(option.temp_dir + '/assets')
        open(option.temp_dir + '/assets/index.html', 'a')
        open(option.temp_dir + '/assets/localhost', 'a')
        open(option.temp_dir + '/assets/`string`', 'a')
        open(option.temp_dir + '/assets/`backtick', 'a')
        open(option.temp_dir + '/assets/l1\nl2', 'a')
        open(option.temp_dir + '/assets/127.0.0.1', 'a')

        assert 'success' in self.conf(
            {
                "listeners": {"*:7080": {"pass": "routes"}},
                "routes": [
                    {"action": {"share": option.temp_dir + "/assets$uri"}}
                ],
            }
        )

    def set_share(self, share):
        assert 'success' in self.conf(share, 'routes/0/action/share')

    def test_njs_template_string(self, temp_dir):
        self.set_share('"`' + temp_dir + '/assets/index.html`"')
        assert self.get()['status'] == 200, 'string'

        self.set_share('"' + temp_dir + '/assets/`string`"')
        assert self.get()['status'] == 200, 'string 2'

        self.set_share('"`' + temp_dir + '/assets/\\\\`backtick`"')
        assert self.get()['status'] == 200, 'escape'

        self.set_share('"`' + temp_dir + '/assets/l1\\nl2`"')
        assert self.get()['status'] == 200, 'multiline'

    def test_njs_template_expression(self, temp_dir):
        def check_expression(expression):
            self.set_share(expression)
            assert self.get()['status'] == 200

        check_expression('"`' + temp_dir + '/assets${uri}`"')
        check_expression('"`' + temp_dir + '/assets${uri}${host}`"')
        check_expression('"`' + temp_dir + '/assets${uri + host}`"')
        check_expression('"`' + temp_dir + '/assets${uri + `${host}`}`"')

    def test_njs_variables(self, temp_dir):
        self.set_share('"`' + temp_dir + '/assets/${host}`"')
        assert self.get()['status'] == 200, 'host'

        self.set_share('"`' + temp_dir + '/assets/${remoteAddr}`"')
        assert self.get()['status'] == 200, 'remoteAddr'

        self.set_share('"`' + temp_dir + '/assets/${headers.Host}`"')
        assert self.get()['status'] == 200, 'headers'

        self.set_share('"`' + temp_dir + '/assets/${cookies.foo}`"')
        assert (
            self.get(
                headers={'Cookie': 'foo=localhost', 'Connection': 'close'}
            )['status']
            == 200
        ), 'cookies'

        self.set_share('"`' + temp_dir + '/assets/${args.foo}`"')
        assert self.get(url='/?foo=localhost')['status'] == 200, 'args'

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
