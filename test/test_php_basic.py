import unittest
import unit

class TestUnitBasic(unit.TestUnitControl):

    def setUpClass():
        unit.TestUnit().check_modules('php')

    conf_app = """
        {
            "app": {
                "type": "php",
                "workers": 1,
                "root": "/app",
                "index": "index.php"
            }
        }
    """

    conf_basic = """
        {
            "listeners": {
                "*:7080": {
                    "application": "app"
                }
            },
            "applications": %s
        }
        """ % (conf_app)

    def test_php_get_applications(self):
        self.put('/applications', self.conf_app)

        resp = self.get()

        self.assertEqual(resp['listeners'], {}, 'listeners')
        self.assertEqual(resp['applications'],
            {
                "app": {
                    "type": "php",
                    "workers": 1,
                    "root": "/app",
                    "index": "index.php"
                }
             },
             'applications')

    def test_php_get_applications_prefix(self):
        self.put('/applications', self.conf_app)

        self.assertEqual(self.get('/applications'),
            {
                "app": {
                    "type": "php",
                    "workers": 1,
                    "root": "/app",
                    "index": "index.php"
                }
            },
            'applications prefix')

    def test_php_get_applications_prefix_2(self):
        self.put('/applications', self.conf_app)

        self.assertEqual(self.get('/applications/app'),
            {
                "type": "php",
                "workers": 1,
                "root": "/app",
                "index": "index.php"
            },
            'applications prefix 2')

    def test_php_get_applications_prefix_3(self):
        self.put('/applications', self.conf_app)

        self.assertEqual(self.get('/applications/app/type'), 'php', 'type')
        self.assertEqual(self.get('/applications/app/workers'), 1, 'workers')

    def test_php_get_listeners(self):
        self.put('/', self.conf_basic)

        self.assertEqual(self.get()['listeners'],
            {"*:7080":{"application":"app"}}, 'listeners')

    def test_php_get_listeners_prefix(self):
        self.put('/', self.conf_basic)

        self.assertEqual(self.get('/listeners'),
            {"*:7080":{"application":"app"}}, 'listeners prefix')

    def test_php_get_listeners_prefix_2(self):
        self.put('/', self.conf_basic)

        self.assertEqual(self.get('/listeners/*:7080'),
            {"application":"app"}, 'listeners prefix 2')

    def test_php_change_listener(self):
        self.put('/', self.conf_basic)
        self.put('/listeners', '{"*:7081":{"application":"app"}}')

        self.assertEqual(self.get('/listeners'),
            {"*:7081": {"application":"app"}}, 'change listener')

    def test_php_add_listener(self):
        self.put('/', self.conf_basic)
        self.put('/listeners/*:7082', '{"application":"app"}')

        self.assertEqual(self.get('/listeners'),
            {
                "*:7080": {
                    "application": "app"
                },
                "*:7082": {
                    "application": "app"
                }
            },
            'add listener')

    def test_php_change_application(self):
        self.put('/', self.conf_basic)

        self.put('/applications/app/workers', '30')
        self.assertEqual(self.get('/applications/app/workers'), 30,
            'change application workers')

        self.put('/applications/app/root', '"/www"')
        self.assertEqual(self.get('/applications/app/root'), '/www',
            'change application root')

    def test_php_delete(self):
        self.put('/', self.conf_basic)

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
