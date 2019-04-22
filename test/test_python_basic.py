from unit.control import TestControl


class TestPythonBasic(TestControl):
    prerequisites = ['python']

    conf_app = {
        "app": {
            "type": "python",
            "processes": {"spare": 0},
            "path": "/app",
            "module": "wsgi",
        }
    }

    conf_basic = {
        "listeners": {"*:7080": {"pass": "applications/app"}},
        "applications": conf_app,
    }

    def test_python_get_empty(self):
        self.assertEqual(
            self.conf_get(), {'listeners': {}, 'applications': {}}, 'empty'
        )

    def test_python_get_prefix_listeners(self):
        self.assertEqual(self.conf_get('listeners'), {}, 'listeners prefix')

    def test_python_get_prefix_applications(self):
        self.assertEqual(
            self.conf_get('applications'), {}, 'applications prefix'
        )

    def test_python_get_applications(self):
        self.conf(self.conf_app, 'applications')

        conf = self.conf_get()

        self.assertEqual(conf['listeners'], {}, 'listeners')
        self.assertEqual(
            conf['applications'],
            {
                "app": {
                    "type": "python",
                    "processes": {"spare": 0},
                    "path": "/app",
                    "module": "wsgi",
                }
            },
            'applications',
        )

    def test_python_get_applications_prefix(self):
        self.conf(self.conf_app, 'applications')

        self.assertEqual(
            self.conf_get('applications'),
            {
                "app": {
                    "type": "python",
                    "processes": {"spare": 0},
                    "path": "/app",
                    "module": "wsgi",
                }
            },
            'applications prefix',
        )

    def test_python_get_applications_prefix_2(self):
        self.conf(self.conf_app, 'applications')

        self.assertEqual(
            self.conf_get('applications/app'),
            {
                "type": "python",
                "processes": {"spare": 0},
                "path": "/app",
                "module": "wsgi",
            },
            'applications prefix 2',
        )

    def test_python_get_applications_prefix_3(self):
        self.conf(self.conf_app, 'applications')

        self.assertEqual(
            self.conf_get('applications/app/type'), 'python', 'type'
        )
        self.assertEqual(
            self.conf_get('applications/app/processes/spare'), 0, 'spare'
        )

    def test_python_get_listeners(self):
        self.conf(self.conf_basic)

        self.assertEqual(
            self.conf_get()['listeners'],
            {"*:7080": {"pass": "applications/app"}},
            'listeners',
        )

    def test_python_get_listeners_prefix(self):
        self.conf(self.conf_basic)

        self.assertEqual(
            self.conf_get('listeners'),
            {"*:7080": {"pass": "applications/app"}},
            'listeners prefix',
        )

    def test_python_get_listeners_prefix_2(self):
        self.conf(self.conf_basic)

        self.assertEqual(
            self.conf_get('listeners/*:7080'),
            {"pass": "applications/app"},
            'listeners prefix 2',
        )

    def test_python_change_listener(self):
        self.conf(self.conf_basic)
        self.conf({"*:7081": {"pass": "applications/app"}}, 'listeners')

        self.assertEqual(
            self.conf_get('listeners'),
            {"*:7081": {"pass": "applications/app"}},
            'change listener',
        )

    def test_python_add_listener(self):
        self.conf(self.conf_basic)
        self.conf({"pass": "applications/app"}, 'listeners/*:7082')

        self.assertEqual(
            self.conf_get('listeners'),
            {
                "*:7080": {"pass": "applications/app"},
                "*:7082": {"pass": "applications/app"},
            },
            'add listener',
        )

    def test_python_change_application(self):
        self.conf(self.conf_basic)

        self.conf('30', 'applications/app/processes/max')
        self.assertEqual(
            self.conf_get('applications/app/processes/max'),
            30,
            'change application max',
        )

        self.conf('"/www"', 'applications/app/path')
        self.assertEqual(
            self.conf_get('applications/app/path'),
            '/www',
            'change application path',
        )

    def test_python_delete(self):
        self.conf(self.conf_basic)

        self.assertIn(
            'error',
            self.conf_delete('applications/app'),
            'delete app before listener',
        )
        self.assertIn(
            'success', self.conf_delete('listeners/*:7080'), 'delete listener'
        )
        self.assertIn(
            'success',
            self.conf_delete('applications/app'),
            'delete app after listener',
        )
        self.assertIn(
            'error', self.conf_delete('applications/app'), 'delete app again'
        )


if __name__ == '__main__':
    TestPythonBasic.main()
