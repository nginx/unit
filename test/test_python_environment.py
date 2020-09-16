from unit.applications.lang.python import TestApplicationPython


class TestPythonEnvironment(TestApplicationPython):
    prerequisites = {'modules': {'python': 'any'}}

    def test_python_environment_name_null(self):
        self.load('environment')

        assert 'error' in self.conf(
            {"va\0r": "val1"}, 'applications/environment/environment'
        ), 'name null'

    def test_python_environment_name_equals(self):
        self.load('environment')

        assert 'error' in self.conf(
            {"var=": "val1"}, 'applications/environment/environment'
        ), 'name equals'

    def test_python_environment_value_null(self):
        self.load('environment')

        assert 'error' in self.conf(
            {"var": "\0val"}, 'applications/environment/environment'
        ), 'value null'

    def test_python_environment_update(self):
        self.load('environment')

        self.conf({"var": "val1"}, 'applications/environment/environment')

        assert (
            self.get(
                headers={
                    'Host': 'localhost',
                    'X-Variables': 'var',
                    'Connection': 'close',
                }
            )['body']
            == 'val1,'
        ), 'set'

        self.conf({"var": "val2"}, 'applications/environment/environment')

        assert (
            self.get(
                headers={
                    'Host': 'localhost',
                    'X-Variables': 'var',
                    'Connection': 'close',
                }
            )['body']
            == 'val2,'
        ), 'update'

    def test_python_environment_replace(self):
        self.load('environment')

        self.conf({"var1": "val1"}, 'applications/environment/environment')

        assert (
            self.get(
                headers={
                    'Host': 'localhost',
                    'X-Variables': 'var1',
                    'Connection': 'close',
                }
            )['body']
            == 'val1,'
        ), 'set'

        self.conf({"var2": "val2"}, 'applications/environment/environment')

        assert (
            self.get(
                headers={
                    'Host': 'localhost',
                    'X-Variables': 'var1,var2',
                    'Connection': 'close',
                }
            )['body']
            == 'val2,'
        ), 'replace'

    def test_python_environment_clear(self):
        self.load('environment')

        self.conf(
            {"var1": "val1", "var2": "val2"},
            'applications/environment/environment',
        )

        assert (
            self.get(
                headers={
                    'Host': 'localhost',
                    'X-Variables': 'var1,var2',
                    'Connection': 'close',
                }
            )['body']
            == 'val1,val2,'
        ), 'set'

        self.conf({}, 'applications/environment/environment')

        assert (
            self.get(
                headers={
                    'Host': 'localhost',
                    'X-Variables': 'var1,var2',
                    'Connection': 'close',
                }
            )['body']
            == ''
        ), 'clear'

    def test_python_environment_replace_default(self):
        self.load('environment')

        home_default = self.get(
            headers={
                'Host': 'localhost',
                'X-Variables': 'HOME',
                'Connection': 'close',
            }
        )['body']

        assert len(home_default) > 1, 'get default'

        self.conf({"HOME": "/"}, 'applications/environment/environment')

        assert (
            self.get(
                headers={
                    'Host': 'localhost',
                    'X-Variables': 'HOME',
                    'Connection': 'close',
                }
            )['body']
            == '/,'
        ), 'replace default'

        self.conf({}, 'applications/environment/environment')

        assert (
            self.get(
                headers={
                    'Host': 'localhost',
                    'X-Variables': 'HOME',
                    'Connection': 'close',
                }
            )['body']
            == home_default
        ), 'restore default'
