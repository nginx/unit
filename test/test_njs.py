from pathlib import Path

import pytest

from unit.applications.proto import ApplicationProto
from unit.option import option
from unit.utils import waitforfiles

prerequisites = {'modules': {'njs': 'any'}}

client = ApplicationProto()


@pytest.fixture(autouse=True)
def setup_method_fixture(temp_dir):
    assert 'success' in client.conf(
        {
            "listeners": {"*:8080": {"pass": "routes"}},
            "routes": [{"action": {"share": f"{temp_dir}/assets$uri"}}],
        }
    )


def create_files(*files):
    assets_dir = f'{option.temp_dir}/assets/'
    Path(assets_dir).mkdir(exist_ok=True)

    _ = [Path(assets_dir + f).touch() for f in files]
    waitforfiles(*[assets_dir + f for f in files])


def set_share(share):
    assert 'success' in client.conf(share, 'routes/0/action/share')


def check_expression(expression, url='/'):
    set_share(f'"`{option.temp_dir}/assets{expression}`"')
    assert client.get(url=url)['status'] == 200


def test_njs_template_string(temp_dir):
    create_files('str', '`string`', '`backtick', 'l1\nl2')

    check_expression('/str')
    check_expression('/\\\\`backtick')
    check_expression('/l1\\nl2')

    set_share(f'"{temp_dir}/assets/`string`"')
    assert client.get()['status'] == 200


def test_njs_template_expression():
    create_files('str', 'localhost')

    check_expression('${uri}', '/str')
    check_expression('${uri}${host}')
    check_expression('${uri + host}')
    check_expression('${uri + `${host}`}')


def test_njs_iteration():
    create_files('Connection,Host', 'close,localhost')

    check_expression('/${Object.keys(headers).sort().join()}')
    check_expression('/${Object.values(headers).sort().join()}')


def test_njs_variables(temp_dir):
    create_files('str', 'localhost', '127.0.0.1')

    check_expression('/${host}')
    check_expression('/${remoteAddr}')
    check_expression('/${headers.Host}')

    set_share(f'"`{temp_dir}/assets/${{cookies.foo}}`"')
    assert (
        client.get(headers={'Cookie': 'foo=str', 'Connection': 'close'})[
            'status'
        ]
        == 200
    ), 'cookies'

    set_share(f'"`{temp_dir}/assets/${{args.foo}}`"')
    assert client.get(url='/?foo=str')['status'] == 200, 'args'

    check_expression('/${vars.header_host}')

    set_share(f'"`{temp_dir}/assets/${{vars[\\"arg_foo\\"]}}`"')
    assert client.get(url='/?foo=str')['status'] == 200, 'vars'

    set_share(f'"`{temp_dir}/assets/${{vars.non_exist}}`"')
    assert client.get()['status'] == 404, 'undefined'

    create_files('undefined')
    assert client.get()['status'] == 200, 'undefined 2'


def test_njs_variables_cacheable(temp_dir):
    create_files('str')

    def check_rewrite(rewrite, uri):
        assert 'success' in client.conf(
            [
                {
                    "action": {
                        "rewrite": rewrite,
                        "share": f"`{temp_dir}/assets{uri}`",
                    },
                },
            ],
            'routes',
        )
        assert client.get()['status'] == 200

    check_rewrite('/str', '${uri}')
    check_rewrite('/str', '${vars.uri}')


def test_njs_variables_cacheable_access_log(findall, temp_dir):
    assert 'success' in client.conf({"return": 200}, 'routes/0/action')

    assert 'success' in client.conf(
        {
            'path': f'{temp_dir}/access.log',
            'format': '`${vars.host}, ${vars.status}\n`',
        },
        'access_log'
    ), 'access_log configure'

    reqs = 50
    for _ in range(reqs):
        client.get()

    assert len(findall(r'localhost, 200', 'access.log')) == reqs


def test_njs_invalid(skip_alert):
    skip_alert(r'js exception:')

    def check_invalid(template):
        assert 'error' in client.conf(template, 'routes/0/action/share')

    check_invalid('"`a"')
    check_invalid('"`a``"')
    check_invalid('"`a`/"')
    check_invalid('"`${vars.}`"')

    def check_invalid_resolve(template):
        assert 'success' in client.conf(template, 'routes/0/action/share')
        assert client.get()['status'] == 500

    check_invalid_resolve('"`${a}`"')
    check_invalid_resolve('"`${uri.a.a}`"')
    check_invalid_resolve('"`${vars.a.a}`"')
