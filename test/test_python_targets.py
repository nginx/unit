from unit.applications.lang.python import ApplicationPython
from unit.option import option

prerequisites = {'modules': {'python': 'all'}}

client = ApplicationPython()


def test_python_targets():
    python_dir = f'{option.test_dir}/python'

    assert 'success' in client.conf(
        {
            "listeners": {"*:8080": {"pass": "routes"}},
            "routes": [
                {
                    "match": {"uri": "/1"},
                    "action": {"pass": "applications/targets/1"},
                },
                {
                    "match": {"uri": "/2"},
                    "action": {"pass": "applications/targets/2"},
                },
            ],
            "applications": {
                "targets": {
                    "type": client.get_application_type(),
                    "working_directory": f'{python_dir}/targets/',
                    "path": f'{python_dir}/targets/',
                    "targets": {
                        "1": {
                            "module": "wsgi",
                            "callable": "wsgi_target_a",
                        },
                        "2": {
                            "module": "wsgi",
                            "callable": "wsgi_target_b",
                        },
                    },
                }
            },
        }
    )

    resp = client.get(url='/1')
    assert resp['status'] == 200
    assert resp['body'] == '1'

    resp = client.get(url='/2')
    assert resp['status'] == 200
    assert resp['body'] == '2'


def test_python_targets_prefix():
    python_dir = f'{option.test_dir}/python'

    assert 'success' in client.conf(
        {
            "listeners": {"*:8080": {"pass": "routes"}},
            "routes": [
                {
                    "match": {"uri": ["/app*"]},
                    "action": {"pass": "applications/targets/app"},
                },
                {
                    "match": {"uri": "*"},
                    "action": {"pass": "applications/targets/catchall"},
                },
            ],
            "applications": {
                "targets": {
                    "type": "python",
                    "working_directory": f'{python_dir}/targets/',
                    "path": f'{python_dir}/targets/',
                    "protocol": "wsgi",
                    "targets": {
                        "app": {
                            "module": "wsgi",
                            "callable": "wsgi_target_prefix",
                            "prefix": "/app/",
                        },
                        "catchall": {
                            "module": "wsgi",
                            "callable": "wsgi_target_prefix",
                            "prefix": "/api",
                        },
                    },
                }
            },
        }
    )

    def check_prefix(url, body):
        resp = client.get(url=url)
        assert resp['status'] == 200
        assert resp['body'] == body

    check_prefix('/app', '/app ')
    check_prefix('/app/', '/app /')
    check_prefix('/app/rest/user/', '/app /rest/user/')
    check_prefix('/catchall', 'No Script Name /catchall')
    check_prefix('/api', '/api ')
    check_prefix('/api/', '/api /')
    check_prefix('/apis', 'No Script Name /apis')
    check_prefix('/api/users/', '/api /users/')
