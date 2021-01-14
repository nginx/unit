from unit.control import TestControl


class TestPythonBasic(TestControl):
    prerequisites = {'modules': {'python': 'any'}}

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
        assert self.conf_get() == {'listeners': {}, 'applications': {}}
        assert self.conf_get('listeners') == {}
        assert self.conf_get('applications') == {}

    def test_python_get_applications(self):
        self.conf(self.conf_app, 'applications')

        conf = self.conf_get()

        assert conf['listeners'] == {}, 'listeners'
        assert conf['applications'] == {
            "app": {
                "type": "python",
                "processes": {"spare": 0},
                "path": "/app",
                "module": "wsgi",
            }
        }, 'applications'

        assert self.conf_get('applications') == {
            "app": {
                "type": "python",
                "processes": {"spare": 0},
                "path": "/app",
                "module": "wsgi",
            }
        }, 'applications prefix'

        assert self.conf_get('applications/app') == {
            "type": "python",
            "processes": {"spare": 0},
            "path": "/app",
            "module": "wsgi",
        }, 'applications prefix 2'

        assert self.conf_get('applications/app/type') == 'python', 'type'
        assert self.conf_get('applications/app/processes/spare') == 0, 'spare'

    def test_python_get_listeners(self):
        assert 'success' in self.conf(self.conf_basic)

        assert self.conf_get()['listeners'] == {
            "*:7080": {"pass": "applications/app"}
        }, 'listeners'

        assert self.conf_get('listeners') == {
            "*:7080": {"pass": "applications/app"}
        }, 'listeners prefix'

        assert self.conf_get('listeners/*:7080') == {
            "pass": "applications/app"
        }, 'listeners prefix 2'

    def test_python_change_listener(self):
        assert 'success' in self.conf(self.conf_basic)
        assert 'success' in self.conf(
            {"*:7081": {"pass": "applications/app"}}, 'listeners'
        )

        assert self.conf_get('listeners') == {
            "*:7081": {"pass": "applications/app"}
        }, 'change listener'

    def test_python_add_listener(self):
        assert 'success' in self.conf(self.conf_basic)
        assert 'success' in self.conf(
            {"pass": "applications/app"}, 'listeners/*:7082'
        )

        assert self.conf_get('listeners') == {
            "*:7080": {"pass": "applications/app"},
            "*:7082": {"pass": "applications/app"},
        }, 'add listener'

    def test_python_change_application(self):
        assert 'success' in self.conf(self.conf_basic)

        assert 'success' in self.conf('30', 'applications/app/processes/max')
        assert (
            self.conf_get('applications/app/processes/max') == 30
        ), 'change application max'

        assert 'success' in self.conf('"/www"', 'applications/app/path')
        assert (
            self.conf_get('applications/app/path') == '/www'
        ), 'change application path'

    def test_python_delete(self):
        assert 'success' in self.conf(self.conf_basic)

        assert 'error' in self.conf_delete('applications/app')
        assert 'success' in self.conf_delete('listeners/*:7080')
        assert 'success' in self.conf_delete('applications/app')
        assert 'error' in self.conf_delete('applications/app')

    def test_python_delete_blocks(self):
        assert 'success' in self.conf(self.conf_basic)

        assert 'success' in self.conf_delete('listeners')
        assert 'success' in self.conf_delete('applications')

        assert 'success' in self.conf(self.conf_app, 'applications')
        assert 'success' in self.conf(
            {"*:7081": {"pass": "applications/app"}}, 'listeners'
        ), 'applications restore'
