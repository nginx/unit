import unittest
import unit

class TestUnitConfiguration(unit.TestUnitControl):

    def setUpClass():
        unit.TestUnit().check_modules('python')

    def test_json(self):
        self.assertIn('error', self.put('/', '00'), 'leading zero')

    def test_json_applications(self):
        self.assertIn('error', self.put('/applications', '"{}"'),
            'applications string')
        self.assertIn('error', self.put('/applications', '{'),
            'applications miss brace')

        self.assertTry('assertIn', 'negative workers', 'error',
            self.put('/applications', """
            {
                "app": {
                    "type": "python",
                    "workers": -1,
                    "path": "/app",
                    "module": "wsgi"
                }
            }
            """))

        self.assertTry('assertIn', 'application type only', 'error',
            self.put('/applications', """
            {
                "app": {
                    "type": "python"
                }
            }
            """))

        self.assertIn('error', self.put('/applications', """
            {
                app": {
                    "type": "python",
                    "workers": 1,
                    "path": "/app",
                    "module": "wsgi"
                }
            }
            """), 'applications miss quote')

        self.assertIn('error', self.put('/applications', """
            {
                "app" {
                    "type": "python",
                    "workers": 1,
                    "path": "/app",
                    "module": "wsgi"
                }
            }
            """), 'applications miss colon')

        self.assertIn('error', self.put('/applications', """
            {
                "app": {
                    "type": "python"
                    "workers": 1,
                    "path": "/app",
                    "module": "wsgi"
                }
            }
            """), 'applications miss comma')

        self.assertIn('success', self.put('/applications', b'{ \n\r\t}'),
            'skip space')

        self.assertIn('success', self.put('/applications', """
            {
                "app": {
                    "type": "python",
                    "workers": 1,
                    "path": "../app",
                    "module": "wsgi"
                }
            }
            """), 'relative path')

        self.assertIn('success', self.put('/applications', b"""
            {
                "ap\u0070": {
                    "type": "\u0070ython",
                    "workers": 1,
                    "path": "\u002Fapp",
                    "module": "wsgi"
                }
            }
            """), 'unicode')

        self.assertIn('success', self.put('/applications', """
            {
                "приложение": {
                    "type": "python",
                    "workers": 1,
                    "path": "/app",
                    "module": "wsgi"
                }
            }
            """), 'unicode 2')

        self.assertIn('error', self.put('/applications', b"""
            {
                "app": {
                    "type": "python",
                    "workers": \u0031,
                    "path": "/app",
                    "module": "wsgi"
                }
            }
            """), 'unicode number')

    def test_json_listeners(self):
        self.assertTry('assertIn', 'listener empty', 'error',
            self.put('/listeners', '{"*:7080":{}}'))
        self.assertIn('error', self.put('/listeners',
            '{"*:7080":{"application":"app"}}'), 'listeners no app')

        self.put('/applications', """
            {
                "app": {
                    "type": "python",
                    "workers": 1,
                    "path": "/app",
                    "module": "wsgi"
                }
            }
            """)

        self.assertIn('success', self.put('/listeners',
            '{"*:7080":{"application":"app"}}'), 'listeners wildcard')
        self.assertIn('success', self.put('/listeners',
            '{"127.0.0.1:7081":{"application":"app"}}'), 'listeners explicit')
        self.assertIn('success', self.put('/listeners',
            '{"[::1]:7082":{"application":"app"}}'), 'listeners explicit ipv6')
        self.assertIn('error', self.put('/listeners',
            '{"127.0.0.1":{"application":"app"}}'), 'listeners no port')

if __name__ == '__main__':
    unittest.main()
