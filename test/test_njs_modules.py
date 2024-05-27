from unit.applications.proto import ApplicationProto
from unit.option import option

prerequisites = {'modules': {'njs': 'any'}}

client = ApplicationProto()


def njs_script_load(module, name=None, expect='success'):
    if name is None:
        name = module

    with open(f'{option.test_dir}/njs/{module}/script.js', 'rb') as script:
        assert expect in client.conf(script.read(), f'/js_modules/{name}')


def test_njs_modules():
    njs_script_load('next')

    assert 'export' in client.conf_get('/js_modules/next')
    assert 'error' in client.conf_post('"blah"', '/js_modules/next')

    assert 'success' in client.conf(
        {
            "settings": {"js_module": "next"},
            "listeners": {"*:8080": {"pass": "routes/first"}},
            "routes": {
                "first": [{"action": {"pass": "`routes/${next.route()}`"}}],
                "next": [{"action": {"return": 200}}],
            },
        }
    )
    assert client.get()['status'] == 200, 'string'

    assert 'success' in client.conf({"js_module": ["next"]}, 'settings')
    assert client.get()['status'] == 200, 'array'

    # add one more value to array

    assert len(client.conf_get('/js_modules').keys()) == 1

    njs_script_load('next', 'next_2')

    assert len(client.conf_get('/js_modules').keys()) == 2

    assert 'success' in client.conf_post('"next_2"', 'settings/js_module')
    assert client.get()['status'] == 200, 'array len 2'

    assert 'success' in client.conf(
        '"`routes/${next_2.route()}`"', 'routes/first/0/action/pass'
    )
    assert client.get()['status'] == 200, 'array new'

    # can't update exsisting script

    njs_script_load('global_this', 'next', expect='error')

    # delete modules

    assert 'error' in client.conf_delete('/js_modules/next_2')
    assert 'success' in client.conf_delete('settings/js_module')
    assert 'success' in client.conf_delete('/js_modules/next_2')


def test_njs_modules_import():
    njs_script_load('import_from')

    assert 'success' in client.conf(
        {
            "settings": {"js_module": "import_from"},
            "listeners": {"*:8080": {"pass": "routes/first"}},
            "routes": {
                "first": [
                    {"action": {"pass": "`routes/${import_from.num()}`"}}
                ],
                "number": [{"action": {"return": 200}}],
            },
        }
    )
    assert client.get()['status'] == 200


def test_njs_modules_this():
    njs_script_load('global_this')

    assert 'success' in client.conf(
        {
            "settings": {"js_module": "global_this"},
            "listeners": {"*:8080": {"pass": "routes/first"}},
            "routes": {
                "first": [
                    {"action": {"pass": "`routes/${global_this.str()}`"}}
                ],
                "string": [{"action": {"return": 200}}],
            },
        }
    )
    assert client.get()['status'] == 200


def test_njs_modules_invalid(skip_alert):
    skip_alert(r'.*JS compile module.*failed.*')

    njs_script_load('invalid', expect='error')
