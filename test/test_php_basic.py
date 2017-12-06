import unit
import unittest

class TestUnitBasic(unit.TestUnitControl):

    @classmethod
    def setUpClass(cls):
        u = unit.TestUnit()
        module_missed = u.check_modules('php')
        if module_missed:
            raise unittest.SkipTest('Unit has no ' + module_missed + ' module')

    def test_php_get(self):
        resp = self.get()
        self.assertEqual(resp, {'listeners': {}, 'applications': {}}, 'empty')
        self.assertEqual(self.get('/listeners'), {}, 'empty listeners prefix')
        self.assertEqual(self.get('/applications'), {},
            'empty applications prefix')

        self.put('/applications', """
            {
                "app": {
                    "type": "php",
                    "workers": 1,
                    "root": "/app",
                    "index": "index.php"
                }
            }
            """)

        resp = self.get()

        self.assertEqual(resp['listeners'], {}, 'php empty listeners')
        self.assertEqual(resp['applications'],
            {
                "app": {
                    "type": "php",
                    "workers": 1,
                    "root": "/app",
                    "index": "index.php"
                }
             },
             'php applications')

        self.assertEqual(self.get('/applications'),
            {
                "app": {
                    "type": "php",
                    "workers": 1,
                    "root": "/app",
                    "index": "index.php"
                }
            },
            'php applications prefix')

        self.assertEqual(self.get('/applications/app'),
            {
                "type": "php",
                "workers": 1,
                "root": "/app",
                "index": "index.php"
            },
            'php applications prefix 2')

        self.assertEqual(self.get('/applications/app/type'), 'php',
            'php applications type')
        self.assertEqual(self.get('/applications/app/workers'), 1,
            'php applications workers')

        self.put('/listeners', '{"*:7080":{"application":"app"}}')

        self.assertEqual(self.get()['listeners'],
            {"*:7080":{"application":"app"}}, 'php listeners')
        self.assertEqual(self.get('/listeners'),
            {"*:7080":{"application":"app"}}, 'php listeners prefix')
        self.assertEqual(self.get('/listeners/*:7080'),
            {"application":"app"}, 'php listeners prefix 2')
        self.assertEqual(self.get('/listeners/*:7080/application'), 'app',
            'php listeners application')

    def test_php_put(self):
        self.put('/', """
            {
                "listeners": {
                    "*:7080": {
                        "application": "app"
                    }
                },
                "applications": {
                    "app": {
                        "type": "php",
                        "workers": 1,
                        "root": "/app",
                        "index": "index.php"
                    }
                }
            }
            """)

        resp = self.get()

        self.assertEqual(resp['listeners'], {"*:7080":{"application":"app"}},
            'put listeners')

        self.assertEqual(resp['applications'],
            {
                "app": {
                    "type": "php",
                    "workers": 1,
                    "root": "/app",
                    "index": "index.php"
                }
            },
            'put applications')

        self.put('/listeners', '{"*:7081":{"application":"app"}}')
        self.assertEqual(self.get('/listeners'),
            {"*:7081": {"application":"app"}}, 'put listeners prefix')

        self.put('/listeners/*:7082', '{"application":"app"}')

        self.assertEqual(self.get('/listeners'),
            {
                "*:7081": {
                    "application": "app"
                },
                "*:7082": {
                    "application": "app"
                }
            },
            'put listeners prefix 3')

        self.put('/applications/app/workers', '30')
        self.assertEqual(self.get('/applications/app/workers'), 30,
            'put applications workers')

        self.put('/applications/app/root', '"/www"')
        self.assertEqual(self.get('/applications/app/root'), '/www',
            'put applications root')

    def test_php_delete(self):
        self.put('/', """
            {
                "listeners": {
                    "*:7080": {
                        "application": "app"
                    }
                },
                "applications": {
                    "app": {
                        "type": "php",
                        "workers": 1,
                        "root": "/app",
                        "index": "index.php"
                    }
                }
            }
            """)

        self.assertIn('error', self.delete('/applications/app'),
            'delete app before listener')
        self.assertIn('success', self.delete('/listeners/*:7080'),
            'delete listener')
        self.assertIn('success', self.delete('/applications/app'),
            'delete app after listener')
        self.assertIn('error', self.delete('/applications/app'),
            'delete app again')

if __name__ == '__main__':
    unittest.main()
