import pytest
from unit.control import TestControl


class TestConfiguration(TestControl):
    prerequisites = {'modules': {'python': 'any'}}

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

    def test_listeners_wildcard(self):
        assert 'success' in self.conf(
            {
                "listeners": {"*:7080": {"pass": "applications/app"}},
                "applications": {
                    "app": {
                        "type": "python",
                        "processes": {"spare": 0},
                        "path": "/app",
                        "module": "wsgi",
                    }
                },
            }
        ), 'listeners wildcard'

    def test_listeners_explicit(self):
        assert 'success' in self.conf(
            {
                "listeners": {"127.0.0.1:7080": {"pass": "applications/app"}},
                "applications": {
                    "app": {
                        "type": "python",
                        "processes": {"spare": 0},
                        "path": "/app",
                        "module": "wsgi",
                    }
                },
            }
        ), 'explicit'

    def test_listeners_explicit_ipv6(self):
        assert 'success' in self.conf(
            {
                "listeners": {"[::1]:7080": {"pass": "applications/app"}},
                "applications": {
                    "app": {
                        "type": "python",
                        "processes": {"spare": 0},
                        "path": "/app",
                        "module": "wsgi",
                    }
                },
            }
        ), 'explicit ipv6'

    @pytest.mark.skip('not yet, unsafe')
    def test_listeners_no_port(self):
        assert 'error' in self.conf(
            {
                "listeners": {"127.0.0.1": {"pass": "applications/app"}},
                "applications": {
                    "app": {
                        "type": "python",
                        "processes": {"spare": 0},
                        "path": "/app",
                        "module": "wsgi",
                    }
                },
            }
        ), 'no port'

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
