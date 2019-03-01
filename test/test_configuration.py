import unittest
import unit

class TestUnitConfiguration(unit.TestUnitControl):

    def setUpClass():
        unit.TestUnit().check_modules('python')

    def test_json_empty(self):
        self.assertIn('error', self.conf(''), 'empty')

    def test_json_leading_zero(self):
        self.assertIn('error', self.conf('00'), 'leading zero')

    def test_json_unicode(self):
        self.assertIn('success', self.conf(b"""
            {
                "ap\u0070": {
                    "type": "\u0070ython",
                    "processes": { "spare": 0 },
                    "path": "\u002Fapp",
                    "module": "wsgi"
                }
            }
            """, 'applications'), 'unicode')

        self.assertDictEqual(self.conf_get('applications'), {
            "app": {
                "type": "python",
                "processes": { "spare": 0 },
                "path": "/app",
                "module": "wsgi"
            }
        }, 'unicode get')

    def test_json_unicode_2(self):
        self.assertIn('success', self.conf({
            "приложение": {
                "type": "python",
                "processes": { "spare": 0 },
                "path": "/app",
                "module": "wsgi"
            }
        }, 'applications'), 'unicode 2')

        self.assertIn('приложение', self.conf_get('applications'),
            'unicode 2 get')

    def test_json_unicode_number(self):
        self.assertIn('error', self.conf(b"""
            {
                "app": {
                    "type": "python",
                    "processes": { "spare": \u0030 },
                    "path": "/app",
                    "module": "wsgi"
                }
            }
            """, 'applications'), 'unicode number')

    def test_applications_open_brace(self):
        self.assertIn('error', self.conf('{', 'applications'), 'open brace')

    def test_applications_string(self):
        self.assertIn('error', self.conf('"{}"', 'applications'), 'string')

    def test_applications_type_only(self):
        self.skip_alerts.extend([
            r'python module is empty',
            r'failed to apply new conf',
            r'process \d+ exited on signal'
        ])

        self.assertIn('error', self.conf({
            "app": {
                "type": "python"
            }
        }, 'applications'), 'type only')

    def test_applications_miss_quote(self):
        self.assertIn('error', self.conf("""
            {
                app": {
                    "type": "python",
                    "processes": { "spare": 0 },
                    "path": "/app",
                    "module": "wsgi"
                }
            }
            """, 'applications'), 'miss quote')

    def test_applications_miss_colon(self):
        self.assertIn('error', self.conf("""
            {
                "app" {
                    "type": "python",
                    "processes": { "spare": 0 },
                    "path": "/app",
                    "module": "wsgi"
                }
            }
            """, 'applications'), 'miss colon')

    def test_applications_miss_comma(self):
        self.assertIn('error', self.conf("""
            {
                "app": {
                    "type": "python"
                    "processes": { "spare": 0 },
                    "path": "/app",
                    "module": "wsgi"
                }
            }
            """, 'applications'), 'miss comma')

    def test_applications_skip_spaces(self):
        self.assertIn('success', self.conf(b'{ \n\r\t}', 'applications'),
            'skip spaces')

    def test_applications_relative_path(self):
        self.assertIn('success', self.conf({
            "app": {
                "type": "python",
                "processes": { "spare": 0 },
                "path": "../app",
                "module": "wsgi"
            }
        }, 'applications'), 'relative path')

    @unittest.expectedFailure
    def test_listeners_empty(self):
        self.skip_sanitizer = True
        self.skip_alerts.extend([
            r'failed to apply previous configuration',
            r'process \d+ exited on signal'
        ])

        self.assertIn('error', self.conf({"*:7080":{}}, 'listeners'),
            'listener empty')

    def test_listeners_no_app(self):
        self.assertIn('error', self.conf({"*:7080":{"application":"app"}},
            'listeners'), 'listeners no app')

    def test_listeners_wildcard(self):
        self.assertIn('success', self.conf({
            "listeners": {
                "*:7080": {
                    "application":"app"
                }
            },
            "applications": {
                "app": {
                    "type": "python",
                    "processes": { "spare": 0 },
                    "path": "/app",
                    "module": "wsgi"
                }
            }
        }), 'listeners wildcard')

    def test_listeners_explicit(self):
        self.assertIn('success', self.conf({
            "listeners": {
                "127.0.0.1:7080": {
                    "application":"app"
                }
            },
            "applications": {
                "app": {
                    "type": "python",
                    "processes": { "spare": 0 },
                    "path": "/app",
                    "module": "wsgi"
                }
            }
        }), 'explicit')

    def test_listeners_explicit_ipv6(self):
        self.assertIn('success', self.conf({
            "listeners": {
                "[::1]:7080": {
                    "application":"app"
                }
            },
            "applications": {
                "app": {
                    "type": "python",
                    "processes": { "spare": 0 },
                    "path": "/app",
                    "module": "wsgi"
                }
            }
        }), 'explicit ipv6')

    def test_listeners_no_port(self):
        self.skip_alerts.extend([
            r'invalid listener "127\.0\.0\.1"',
            r'failed to apply new conf',
            r'process \d+ exited on signal'
        ])

        self.assertIn('error', self.conf({
            "listeners": {
                "127.0.0.1": {
                    "application":"app"
                }
            },
            "applications": {
                "app": {
                    "type": "python",
                    "processes": { "spare": 0 },
                    "path": "/app",
                    "module": "wsgi"
                }
            }
        }), 'no port')

    @unittest.expectedFailure
    def test_json_application_name_large(self):
        self.skip_alerts.append(r'epoll_ctl.+failed')
        name = "X" * 1024 * 1024

        self.assertIn('success', self.conf({
            "listeners": {
                "*:7080": {
                    "application": name
                }
            },
            "applications": {
                name: {
                    "type": "python",
                    "processes": { "spare": 0 },
                    "path": "/app",
                    "module": "wsgi"
                }
            }
        }))

    @unittest.expectedFailure
    def test_json_application_many(self):
        self.skip_alerts.extend([
            r'eventfd.+failed',
            r'epoll_create.+failed',
            r'failed to apply new conf'
        ])
        apps = 999

        conf = {
            "applications":
                {"app-" + str(a): {
                    "type": "python",
                    "processes": { "spare": 0 },
                    "path": "/app",
                    "module": "wsgi"
                } for a in range(apps)
            },
            "listeners": {
                "*:" + str(7000 + a): {
                    "application": "app-" + str(a)
                } for a in range(apps)
            }
        }

        self.assertIn('success', self.conf(conf))

if __name__ == '__main__':
    TestUnitConfiguration.main()
