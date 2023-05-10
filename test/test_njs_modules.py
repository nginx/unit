from unit.applications.proto import TestApplicationProto
from unit.option import option


class TestNJSModules(TestApplicationProto):
    prerequisites = {'modules': {'njs': 'any'}}

    def njs_script_load(self, module, name=None, expect='success'):
        if name is None:
            name = module

        with open(f'{option.test_dir}/njs/{module}/script.js', 'rb') as s:
            assert expect in self.conf(s.read(), f'/js_modules/{name}')

    def test_njs_modules(self):
        self.njs_script_load('next')

        assert 'export' in self.conf_get('/js_modules/next')
        assert 'error' in self.conf_post('"blah"', '/js_modules/next')

        assert 'success' in self.conf(
            {
                "settings": {"js_module": "next"},
                "listeners": {"*:7080": {"pass": "routes/first"}},
                "routes": {
                    "first": [{"action": {"pass": "`routes/${next.route()}`"}}],
                    "next": [{"action": {"return": 200}}],
                },
            }
        )
        assert self.get()['status'] == 200, 'string'

        assert 'success' in self.conf({"js_module": ["next"]}, 'settings')
        assert self.get()['status'] == 200, 'array'

        # add one more value to array

        assert len(self.conf_get('/js_modules').keys()) == 1

        self.njs_script_load('next', 'next_2')

        assert len(self.conf_get('/js_modules').keys()) == 2

        assert 'success' in self.conf_post('"next_2"', 'settings/js_module')
        assert self.get()['status'] == 200, 'array len 2'

        assert 'success' in self.conf(
            '"`routes/${next_2.route()}`"', 'routes/first/0/action/pass'
        )
        assert self.get()['status'] == 200, 'array new'

        # can't update exsisting script

        self.njs_script_load('global_this', 'next', expect='error')

        # delete modules

        assert 'error' in self.conf_delete('/js_modules/next_2')
        assert 'success' in self.conf_delete('settings/js_module')
        assert 'success' in self.conf_delete('/js_modules/next_2')

    def test_njs_modules_import(self):
        self.njs_script_load('import_from')

        assert 'success' in self.conf(
            {
                "settings": {"js_module": "import_from"},
                "listeners": {"*:7080": {"pass": "routes/first"}},
                "routes": {
                    "first": [
                        {"action": {"pass": "`routes/${import_from.num()}`"}}
                    ],
                    "number": [{"action": {"return": 200}}],
                },
            }
        )
        assert self.get()['status'] == 200

    def test_njs_modules_this(self):
        self.njs_script_load('global_this')

        assert 'success' in self.conf(
            {
                "settings": {"js_module": "global_this"},
                "listeners": {"*:7080": {"pass": "routes/first"}},
                "routes": {
                    "first": [
                        {"action": {"pass": "`routes/${global_this.str()}`"}}
                    ],
                    "string": [{"action": {"return": 200}}],
                },
            }
        )
        assert self.get()['status'] == 200

    def test_njs_modules_invalid(self, skip_alert):
        skip_alert(r'.*JS compile module.*failed.*')

        self.njs_script_load('invalid', expect='error')
