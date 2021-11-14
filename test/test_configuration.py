import socket

import pytest
from unit.control import TestControl
from unit.option import option


class TestConfiguration(TestControl):
    prerequisites = {'modules': {'python': 'any'}}

    def try_addr(self, addr):
        return self.conf(
            {
                "listeners": {addr: {"pass": "routes"}},
                "routes": [{"action": {"return": 200}}],
                "applications": {},
            }
        )

    def test_json_empty(self):
        assert 'error' in self.conf(''), 'empty'

    def test_json_leading_zero(self):
        assert 'error' in self.conf('00'), 'leading zero'

    def test_json_unicode(self):
        assert 'success' in self.conf(
            u"""
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

        assert self.conf_get('applications') == {
            "app": {
                "type": "python",
                "processes": {"spare": 0},
                "path": "/app",
                "module": "wsgi",
            }
        }, 'unicode get'

    def test_json_unicode_2(self):
        assert 'success' in self.conf(
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

        assert 'приложение' in self.conf_get('applications'), 'unicode 2 get'

    def test_json_unicode_number(self):
        assert 'success' in self.conf(
            u"""
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

    def test_json_utf8_bom(self):
        assert 'success' in self.conf(
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

    def test_json_comment_single_line(self):
        assert 'success' in self.conf(
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

    def test_json_comment_multi_line(self):
        assert 'success' in self.conf(
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

    def test_json_comment_invalid(self):
        assert 'error' in self.conf(b'/{}', 'applications'), 'slash'
        assert 'error' in self.conf(b'//{}', 'applications'), 'comment'
        assert 'error' in self.conf(b'{} /', 'applications'), 'slash end'
        assert 'error' in self.conf(b'/*{}', 'applications'), 'slash star'
        assert 'error' in self.conf(b'{} /*', 'applications'), 'slash star end'

    def test_applications_open_brace(self):
        assert 'error' in self.conf('{', 'applications'), 'open brace'

    def test_applications_string(self):
        assert 'error' in self.conf('"{}"', 'applications'), 'string'

    @pytest.mark.skip('not yet, unsafe')
    def test_applications_type_only(self):
        assert 'error' in self.conf(
            {"app": {"type": "python"}}, 'applications'
        ), 'type only'

    def test_applications_miss_quote(self):
        assert 'error' in self.conf(
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

    def test_applications_miss_colon(self):
        assert 'error' in self.conf(
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

    def test_applications_miss_comma(self):
        assert 'error' in self.conf(
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

    def test_applications_skip_spaces(self):
        assert 'success' in self.conf(
            b'{ \n\r\t}', 'applications'
        ), 'skip spaces'

    def test_applications_relative_path(self):
        assert 'success' in self.conf(
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
    def test_listeners_empty(self):
        assert 'error' in self.conf(
            {"*:7080": {}}, 'listeners'
        ), 'listener empty'

    def test_listeners_no_app(self):
        assert 'error' in self.conf(
            {"*:7080": {"pass": "applications/app"}}, 'listeners'
        ), 'listeners no app'

    def test_listeners_unix_abstract(self):
        if option.system != 'Linux':
            assert 'error' in self.try_addr("unix:@sock"), 'abstract at'

        pytest.skip('not yet')

        assert 'error' in self.try_addr("unix:\0soc"), 'abstract \0'
        assert 'error' in self.try_addr("unix:\u0000soc"), 'abstract \0 unicode'

    def test_listeners_addr(self):
        assert 'success' in self.try_addr("*:7080"), 'wildcard'
        assert 'success' in self.try_addr("127.0.0.1:7081"), 'explicit'
        assert 'success' in self.try_addr("[::1]:7082"), 'explicit ipv6'

    def test_listeners_addr_error(self):
        assert 'error' in self.try_addr("127.0.0.1"), 'no port'

    def test_listeners_addr_error_2(self, skip_alert):
        skip_alert(r'bind.*failed', r'failed to apply new conf')

        assert 'error' in self.try_addr(
            "[f607:7403:1e4b:6c66:33b2:843f:2517:da27]:7080"
        )

    def test_listeners_port_release(self):
        for i in range(10):
            fail = False
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

                self.conf(
                    {
                        "listeners": {"127.0.0.1:7080": {"pass": "routes"}},
                        "routes": [],
                    }
                )

                resp = self.conf({"listeners": {}, "applications": {}})

                try:
                    s.bind(('127.0.0.1', 7080))
                    s.listen()

                except OSError:
                    fail = True

                if fail:
                    pytest.fail('cannot bind or listen to the address')

                assert 'success' in resp, 'port release'

    def test_json_application_name_large(self):
        name = "X" * 1024 * 1024

        assert 'success' in self.conf(
            {
                "listeners": {"*:7080": {"pass": "applications/" + name}},
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
    def test_json_application_many(self):
        apps = 999

        conf = {
            "applications": {
                "app-"
                + str(a): {
                    "type": "python",
                    "processes": {"spare": 0},
                    "path": "/app",
                    "module": "wsgi",
                }
                for a in range(apps)
            },
            "listeners": {
                "*:" + str(7000 + a): {"pass": "applications/app-" + str(a)}
                for a in range(apps)
            },
        }

        assert 'success' in self.conf(conf)

    def test_json_application_python_prefix(self):
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
            "listeners": {"*:7080": {"pass": "routes"}},
            "routes": [
                {
                    "match": {"uri": "/app/*"},
                    "action": {"pass": "applications/sub-app"},
                }
            ],
        }

        assert 'success' in self.conf(conf)

    def test_json_application_prefix_target(self):
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
            "listeners": {"*:7080": {"pass": "routes"}},
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

        assert 'success' in self.conf(conf)

    def test_json_application_invalid_python_prefix(self):
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
            "listeners": {"*:7080": {"pass": "applications/sub-app"}},
        }

        assert 'error' in self.conf(conf)

    def test_json_application_empty_python_prefix(self):
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
            "listeners": {"*:7080": {"pass": "applications/sub-app"}},
        }

        assert 'error' in self.conf(conf)

    def test_json_application_many2(self):
        conf = {
            "applications": {
                "app-"
                + str(a): {
                    "type": "python",
                    "processes": {"spare": 0},
                    "path": "/app",
                    "module": "wsgi",
                }
                # Larger number of applications can cause test fail with default
                # open files limit due to the lack of file descriptors.
                for a in range(100)
            },
            "listeners": {"*:7080": {"pass": "applications/app-1"}},
        }

        assert 'success' in self.conf(conf)

    def test_unprivileged_user_error(self, is_su, skip_alert):
        skip_alert(r'cannot set user "root"', r'failed to apply new conf')
        if is_su:
            pytest.skip('unprivileged tests')

        assert 'error' in self.conf(
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
