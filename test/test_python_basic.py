import unittest
import unit

class TestUnitBasic(unit.TestUnitControl):

    def setUpClass():
        unit.TestUnit().check_modules('python')

    conf_app = """
        {
            "app": {
                "type": "python",
                "workers": 1,
                "path": "/app",
                "module": "wsgi"
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

    def test_python_get_empty(self):
        self.assertEqual(self.get(), {'listeners': {}, 'applications': {}},
            'empty')

    def test_python_get_prefix_listeners(self):
        self.assertEqual(self.get('/listeners'), {}, 'listeners prefix')

    def test_python_get_prefix_applications(self):
        self.assertEqual(self.get('/applications'), {}, 'applications prefix')

    def test_python_get_applications(self):
        self.put('/applications', self.conf_app)

        resp = self.get()

        self.assertEqual(resp['listeners'], {}, 'listeners')
        self.assertEqual(resp['applications'],
            {
                "app": {
                    "type": "python",
                    "workers": 1,
                    "path": "/app",
                    "module": "wsgi"
                }
             },
             'applications')

    def test_python_get_applications_prefix(self):
        self.put('/applications', self.conf_app)

        self.assertEqual(self.get('/applications'),
            {
                "app": {
                    "type": "python",
                    "workers": 1,
                    "path": "/app",
                    "module":"wsgi"
                }
            },
            'applications prefix')

    def test_python_get_applications_prefix_2(self):
        self.put('/applications', self.conf_app)

        self.assertEqual(self.get('/applications/app'),
            {
                "type": "python",
                "workers": 1,
                "path": "/app",
                "module": "wsgi"
            },
            'applications prefix 2')

    def test_python_get_applications_prefix_3(self):
        self.put('/applications', self.conf_app)

        self.assertEqual(self.get('/applications/app/type'), 'python', 'type')
        self.assertEqual(self.get('/applications/app/workers'), 1, 'workers')

    def test_python_get_listeners(self):
        self.put('/', self.conf_basic)

        self.assertEqual(self.get()['listeners'],
            {"*:7080":{"application":"app"}}, 'listeners')

    def test_python_get_listeners_prefix(self):
        self.put('/', self.conf_basic)

        self.assertEqual(self.get('/listeners'),
            {"*:7080":{"application":"app"}}, 'listeners prefix')

    def test_python_get_listeners_prefix_2(self):
        self.put('/', self.conf_basic)

        self.assertEqual(self.get('/listeners/*:7080'),
            {"application":"app"}, 'listeners prefix 2')

    def test_python_change_listener(self):
        self.put('/', self.conf_basic)
        self.put('/listeners', '{"*:7081":{"application":"app"}}')

        self.assertEqual(self.get('/listeners'),
            {"*:7081": {"application":"app"}}, 'change listener')

    def test_python_add_listener(self):
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

    def test_python_change_application(self):
        self.put('/', self.conf_basic)

        self.put('/applications/app/workers', '30')
        self.assertEqual(self.get('/applications/app/workers'), 30,
            'change application workers')

        self.put('/applications/app/path', '"/www"')
        self.assertEqual(self.get('/applications/app/path'), '/www',
            'change application path')

    def test_python_delete(self):
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
