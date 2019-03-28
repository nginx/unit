from unit.applications.lang.python import TestApplicationPython


class TestPythonEnvironment(TestApplicationPython):
    def setUpClass():
        TestApplicationPython().check_modules('python')

    def test_python_environment_name_null(self):
        self.load('environment')

        self.assertIn(
            'error',
            self.conf(
                {"va\0r": "val1"}, 'applications/environment/environment'
            ),
            'name null',
        )

    def test_python_environment_name_equals(self):
        self.load('environment')

        self.assertIn(
            'error',
            self.conf(
                {"var=": "val1"}, 'applications/environment/environment'
            ),
            'name equals',
        )

    def test_python_environment_value_null(self):
        self.load('environment')

        self.assertIn(
            'error',
            self.conf(
                {"var": "\0val"}, 'applications/environment/environment'
            ),
            'value null',
        )

    def test_python_environment_update(self):
        self.load('environment')

        self.conf({"var": "val1"}, 'applications/environment/environment')

        self.assertEqual(
            self.get(
                headers={
                    'Host': 'localhost',
                    'X-Variables': 'var',
                    'Connection': 'close',
                }
            )['body'],
            'val1,',
            'set',
        )

        self.conf({"var": "val2"}, 'applications/environment/environment')

        self.assertEqual(
            self.get(
                headers={
                    'Host': 'localhost',
                    'X-Variables': 'var',
                    'Connection': 'close',
                }
            )['body'],
            'val2,',
            'update',
        )

    def test_python_environment_replace(self):
        self.load('environment')

        self.conf({"var1": "val1"}, 'applications/environment/environment')

        self.assertEqual(
            self.get(
                headers={
                    'Host': 'localhost',
                    'X-Variables': 'var1',
                    'Connection': 'close',
                }
            )['body'],
            'val1,',
            'set',
        )

        self.conf({"var2": "val2"}, 'applications/environment/environment')

        self.assertEqual(
            self.get(
                headers={
                    'Host': 'localhost',
                    'X-Variables': 'var1,var2',
                    'Connection': 'close',
                }
            )['body'],
            'val2,',
            'replace',
        )

    def test_python_environment_clear(self):
        self.load('environment')

        self.conf(
            {"var1": "val1", "var2": "val2"},
            'applications/environment/environment',
        )

        self.assertEqual(
            self.get(
                headers={
                    'Host': 'localhost',
                    'X-Variables': 'var1,var2',
                    'Connection': 'close',
                }
            )['body'],
            'val1,val2,',
            'set',
        )

        self.conf({}, 'applications/environment/environment')

        self.assertEqual(
            self.get(
                headers={
                    'Host': 'localhost',
                    'X-Variables': 'var1,var2',
                    'Connection': 'close',
                }
            )['body'],
            '',
            'clear',
        )

    def test_python_environment_replace_default(self):
        self.load('environment')

        pwd_default = self.get(
            headers={
                'Host': 'localhost',
                'X-Variables': 'PWD',
                'Connection': 'close',
            }
        )['body']

        self.assertGreater(len(pwd_default), 1, 'get default')

        self.conf({"PWD": "new/pwd"}, 'applications/environment/environment')

        self.assertEqual(
            self.get(
                headers={
                    'Host': 'localhost',
                    'X-Variables': 'PWD',
                    'Connection': 'close',
                }
            )['body'],
            'new/pwd,',
            'replace default',
        )

        self.conf({}, 'applications/environment/environment')

        self.assertEqual(
            self.get(
                headers={
                    'Host': 'localhost',
                    'X-Variables': 'PWD',
                    'Connection': 'close',
                }
            )['body'],
            pwd_default,
            'restore default',
        )


if __name__ == '__main__':
    TestPythonEnvironment.main()
