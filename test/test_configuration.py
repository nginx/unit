import socket

import pytest

from unit.control import Control

prerequisites = {'modules': {'python': 'any'}}

client = Control()


def try_addr(addr):
    return client.conf(
        {
            "listeners": {addr: {"pass": "routes"}},
            "routes": [{"action": {"return": 200}}],
            "applications": {},
        }
    )


def test_json_empty():
    assert 'error' in client.conf(''), 'empty'


def test_json_leading_zero():
    assert 'error' in client.conf('00'), 'leading zero'


def test_json_unicode():
    assert 'success' in client.conf(
        """
        {
            "ap\u0070": {
                "type": "\u0070ython",
                "processes": { "spare": 0 },
                "path": "\u002Fapp",
                "module": "wsgi"
            }
        }
        """,
        'applications',
    ), 'unicode'

    assert client.conf_get('applications') == {
        "app": {
            "type": "python",
            "processes": {"spare": 0},
            "path": "/app",
            "module": "wsgi",
        }
    }, 'unicode get'


def test_json_unicode_2():
    assert 'success' in client.conf(
        {
            "приложение": {
                "type": "python",
                "processes": {"spare": 0},
                "path": "/app",
                "module": "wsgi",
            }
        },
        'applications',
    ), 'unicode 2'

    assert 'приложение' in client.conf_get('applications')


def test_json_unicode_number():
    assert 'success' in client.conf(
        """
        {
            "app": {
                "type": "python",
                "processes": { "spare": \u0030 },
                "path": "/app",
                "module": "wsgi"
            }
        }
        """,
        'applications',
    ), 'unicode number'


def test_json_utf8_bom():
    assert 'success' in client.conf(
        b"""\xEF\xBB\xBF
        {
            "app": {
                "type": "python",
                "processes": {"spare": 0},
                "path": "/app",
                "module": "wsgi"
            }
        }
        """,
        'applications',
    ), 'UTF-8 BOM'


def test_json_comment_single_line():
    assert 'success' in client.conf(
        b"""
        // this is bridge
        {
            "//app": {
                "type": "python", // end line
                "processes": {"spare": 0},
                // inside of block
                "path": "/app",
                "module": "wsgi"
            }
            // double //
        }
        // end of json \xEF\t
        """,
        'applications',
    ), 'single line comments'


def test_json_comment_multi_line():
    assert 'success' in client.conf(
        b"""
        /* this is bridge */
        {
            "/*app": {
            /**
             * multiple lines
             **/
                "type": "python",
                "processes": /* inline */ {"spare": 0},
                "path": "/app",
                "module": "wsgi"
                /*
                // end of block */
            }
            /* blah * / blah /* blah */
        }
        /* end of json \xEF\t\b */
        """,
        'applications',
    ), 'multi line comments'


def test_json_comment_invalid():
    assert 'error' in client.conf(b'/{}', 'applications'), 'slash'
    assert 'error' in client.conf(b'//{}', 'applications'), 'comment'
    assert 'error' in client.conf(b'{} /', 'applications'), 'slash end'
    assert 'error' in client.conf(b'/*{}', 'applications'), 'slash star'
    assert 'error' in client.conf(b'{} /*', 'applications'), 'slash star end'


def test_applications_open_brace():
    assert 'error' in client.conf('{', 'applications'), 'open brace'


def test_applications_string():
    assert 'error' in client.conf('"{}"', 'applications'), 'string'


@pytest.mark.skip('not yet, unsafe')
def test_applications_type_only():
    assert 'error' in client.conf(
        {"app": {"type": "python"}}, 'applications'
    ), 'type only'


def test_applications_miss_quote():
    assert 'error' in client.conf(
        """
        {
            app": {
                "type": "python",
                "processes": { "spare": 0 },
                "path": "/app",
                "module": "wsgi"
            }
        }
        """,
        'applications',
    ), 'miss quote'


def test_applications_miss_colon():
    assert 'error' in client.conf(
        """
        {
            "app" {
                "type": "python",
                "processes": { "spare": 0 },
                "path": "/app",
                "module": "wsgi"
            }
        }
        """,
        'applications',
    ), 'miss colon'


def test_applications_miss_comma():
    assert 'error' in client.conf(
        """
        {
            "app": {
                "type": "python"
                "processes": { "spare": 0 },
                "path": "/app",
                "module": "wsgi"
            }
        }
        """,
        'applications',
    ), 'miss comma'


def test_applications_skip_spaces():
    assert 'success' in client.conf(b'{ \n\r\t}', 'applications'), 'skip spaces'


def test_applications_relative_path():
    assert 'success' in client.conf(
        {
            "app": {
                "type": "python",
                "processes": {"spare": 0},
                "path": "../app",
                "module": "wsgi",
            }
        },
        'applications',
    ), 'relative path'


@pytest.mark.skip('not yet, unsafe')
def test_listeners_empty():
    assert 'error' in client.conf({"*:8080": {}}, 'listeners'), 'listener empty'


def test_listeners_no_app():
    assert 'error' in client.conf(
        {"*:8080": {"pass": "applications/app"}}, 'listeners'
    ), 'listeners no app'


def test_listeners_unix_abstract(system):
    if system != 'Linux':
        assert 'error' in try_addr("unix:@sock"), 'abstract at'

    pytest.skip('not yet')

    assert 'error' in try_addr("unix:\0soc"), 'abstract \0'
    assert 'error' in try_addr("unix:\u0000soc"), 'abstract \0 unicode'


def test_listeners_addr():
    assert 'success' in try_addr("*:8080"), 'wildcard'
    assert 'success' in try_addr("127.0.0.1:8081"), 'explicit'
    assert 'success' in try_addr("[::1]:8082"), 'explicit ipv6'


def test_listeners_addr_error():
    assert 'error' in try_addr("127.0.0.1"), 'no port'


def test_listeners_addr_error_2(skip_alert):
    skip_alert(r'bind.*failed', r'failed to apply new conf')

    assert 'error' in try_addr("[f607:7403:1e4b:6c66:33b2:843f:2517:da27]:8080")


def test_listeners_port_release():
    for _ in range(10):
        fail = False
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            client.conf(
                {
                    "listeners": {"127.0.0.1:8080": {"pass": "routes"}},
                    "routes": [],
                }
            )

            resp = client.conf({"listeners": {}, "applications": {}})

            try:
                s.bind(('127.0.0.1', 8080))
                s.listen()

            except OSError:
                fail = True

            if fail:
                pytest.fail('cannot bind or listen to the address')

            assert 'success' in resp, 'port release'


def test_json_application_name_large():
    name = "X" * 1024 * 1024

    assert 'success' in client.conf(
        {
            "listeners": {"*:8080": {"pass": f"applications/{name}"}},
            "applications": {
                name: {
                    "type": "python",
                    "processes": {"spare": 0},
                    "path": "/app",
                    "module": "wsgi",
                }
            },
        }
    )


@pytest.mark.skip('not yet')
def test_json_application_many():
    apps = 999

    conf = {
        "applications": {
            f"app-{a}": {
                "type": "python",
                "processes": {"spare": 0},
                "path": "/app",
                "module": "wsgi",
            }
            for a in range(apps)
        },
        "listeners": {
            f"*:{(7000 + a)}": {"pass": f"applications/app-{a}"}
            for a in range(apps)
        },
    }

    assert 'success' in client.conf(conf)


def test_json_application_python_prefix():
    conf = {
        "applications": {
            "sub-app": {
                "type": "python",
                "processes": {"spare": 0},
                "path": "/app",
                "module": "wsgi",
                "prefix": "/app",
            }
        },
        "listeners": {"*:8080": {"pass": "routes"}},
        "routes": [
            {
                "match": {"uri": "/app/*"},
                "action": {"pass": "applications/sub-app"},
            }
        ],
    }

    assert 'success' in client.conf(conf)


def test_json_application_prefix_target():
    conf = {
        "applications": {
            "sub-app": {
                "type": "python",
                "processes": {"spare": 0},
                "path": "/app",
                "targets": {
                    "foo": {"module": "foo.wsgi", "prefix": "/app"},
                    "bar": {
                        "module": "bar.wsgi",
                        "callable": "bar",
                        "prefix": "/api",
                    },
                },
            }
        },
        "listeners": {"*:8080": {"pass": "routes"}},
        "routes": [
            {
                "match": {"uri": "/app/*"},
                "action": {"pass": "applications/sub-app/foo"},
            },
            {
                "match": {"uri": "/api/*"},
                "action": {"pass": "applications/sub-app/bar"},
            },
        ],
    }

    assert 'success' in client.conf(conf)


def test_json_application_invalid_python_prefix():
    conf = {
        "applications": {
            "sub-app": {
                "type": "python",
                "processes": {"spare": 0},
                "path": "/app",
                "module": "wsgi",
                "prefix": "app",
            }
        },
        "listeners": {"*:8080": {"pass": "applications/sub-app"}},
    }

    assert 'error' in client.conf(conf)


def test_json_application_empty_python_prefix():
    conf = {
        "applications": {
            "sub-app": {
                "type": "python",
                "processes": {"spare": 0},
                "path": "/app",
                "module": "wsgi",
                "prefix": "",
            }
        },
        "listeners": {"*:8080": {"pass": "applications/sub-app"}},
    }

    assert 'error' in client.conf(conf)


def test_json_application_many2():
    conf = {
        "applications": {
            f"app-{a}": {
                "type": "python",
                "processes": {"spare": 0},
                "path": "/app",
                "module": "wsgi",
            }
            # Larger number of applications can cause test fail with default
            # open files limit due to the lack of file descriptors.
            for a in range(100)
        },
        "listeners": {"*:8080": {"pass": "applications/app-1"}},
    }

    assert 'success' in client.conf(conf)


def test_unprivileged_user_error(require, skip_alert):
    require({'privileged_user': False})

    skip_alert(r'cannot set user "root"', r'failed to apply new conf')

    assert 'error' in client.conf(
        {
            "app": {
                "type": "external",
                "processes": 1,
                "executable": "/app",
                "user": "root",
            }
        },
        'applications',
    ), 'setting user'
