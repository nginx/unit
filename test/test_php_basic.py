import unittest
import unit

class TestUnitPHPBasic(unit.TestUnitControl):

    def setUpClass():
        unit.TestUnit().check_modules('php')

    conf_app = {
        "app": {
            "type": "php",
            "processes": { "spare": 0 },
            "root": "/app",
            "index": "index.php"
        }
    }

    conf_basic = {
        "listeners": {
            "*:7080": {
                "application": "app"
            }
        },
        "applications": conf_app
    }

    def test_php_get_applications(self):
        self.conf(self.conf_app, 'applications')

        conf = self.conf_get()

        self.assertEqual(conf['listeners'], {}, 'listeners')
        self.assertEqual(conf['applications'],
            {
                "app": {
                    "type": "php",
                    "processes": { "spare": 0 },
                    "root": "/app",
                    "index": "index.php"
                }
             },
             'applications')

    def test_php_get_applications_prefix(self):
        self.conf(self.conf_app, 'applications')

        self.assertEqual(self.conf_get('applications'),
            {
                "app": {
                    "type": "php",
                    "processes": { "spare": 0 },
                    "root": "/app",
                    "index": "index.php"
                }
            },
            'applications prefix')

    def test_php_get_applications_prefix_2(self):
        self.conf(self.conf_app, 'applications')

        self.assertEqual(self.conf_get('applications/app'),
            {
                "type": "php",
                "processes": { "spare": 0 },
                "root": "/app",
                "index": "index.php"
            },
            'applications prefix 2')

    def test_php_get_applications_prefix_3(self):
        self.conf(self.conf_app, 'applications')

        self.assertEqual(self.conf_get('applications/app/type'), 'php',
            'type')
        self.assertEqual(self.conf_get('applications/app/processes/spare'), 0,
            'spare processes')

    def test_php_get_listeners(self):
        self.conf(self.conf_basic)

        self.assertEqual(self.conf_get()['listeners'],
            {"*:7080":{"application":"app"}}, 'listeners')

    def test_php_get_listeners_prefix(self):
        self.conf(self.conf_basic)

        self.assertEqual(self.conf_get('listeners'),
            {"*:7080":{"application":"app"}}, 'listeners prefix')

    def test_php_get_listeners_prefix_2(self):
        self.conf(self.conf_basic)

        self.assertEqual(self.conf_get('listeners/*:7080'),
            {"application":"app"}, 'listeners prefix 2')

    def test_php_change_listener(self):
        self.conf(self.conf_basic)
        self.conf({"*:7081":{"application":"app"}}, 'listeners')

        self.assertEqual(self.conf_get('listeners'),
            {"*:7081": {"application":"app"}}, 'change listener')

    def test_php_add_listener(self):
        self.conf(self.conf_basic)
        self.conf({"application":"app"}, 'listeners/*:7082')

        self.assertEqual(self.conf_get('listeners'),
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
        self.conf(self.conf_basic)

        self.conf('30', 'applications/app/processes/max')
        self.assertEqual(self.conf_get('applications/app/processes/max'), 30,
            'change application max')

        self.conf('"/www"', 'applications/app/root')
        self.assertEqual(self.conf_get('applications/app/root'), '/www',
            'change application root')

    def test_php_delete(self):
        self.conf(self.conf_basic)

        self.assertIn('error', self.conf_delete('applications/app'),
            'delete app before listener')
        self.assertIn('success', self.conf_delete('listeners/*:7080'),
            'delete listener')
        self.assertIn('success', self.conf_delete('applications/app'),
            'delete app after listener')
        self.assertIn('error', self.conf_delete('applications/app'),
            'delete app again')

if __name__ == '__main__':
    TestUnitPHPBasic.main()
