from unit.applications.lang.python import ApplicationPython
from unit.option import option

prerequisites = {"modules": {"python": "all"}}

client = ApplicationPython()


def test_python_factory_targets():
    python_dir = f"{option.test_dir}/python"

    assert "success" in client.conf(
        {
            "listeners": {
                "*:8080": {"pass": "applications/targets/1"},
                "*:8081": {"pass": "applications/targets/2"},
                "*:8082": {"pass": "applications/targets/factory-1"},
                "*:8083": {"pass": "applications/targets/factory-2"},
            },
            "applications": {
                "targets": {
                    "type": client.get_application_type(),
                    "working_directory": f"{python_dir}/factory/",
                    "path": f"{python_dir}/factory/",
                    "targets": {
                        "1": {
                            "module": "wsgi",
                            "callable": "wsgi_a",
                            "factory": False,
                        },
                        "2": {
                            "module": "wsgi",
                            "callable": "wsgi_b",
                            "factory": False,
                        },
                        "factory-1": {
                            "module": "wsgi",
                            "callable": "wsgi_a_factory",
                            "factory": True,
                        },
                        "factory-2": {
                            "module": "wsgi",
                            "callable": "wsgi_b_factory",
                            "factory": True,
                        },
                    },
                }
            },
        }
    )

    resp = client.get(port=8080)
    assert resp["status"] == 200
    assert resp["body"] == "1"

    resp = client.get(port=8081)
    assert resp["status"] == 200
    assert resp["body"] == "2"

    resp = client.get(port=8082)
    assert resp["status"] == 200
    assert resp["body"] == "1"

    resp = client.get(port=8083)
    assert resp["status"] == 200
    assert resp["body"] == "2"


def test_python_factory_without_targets():
    python_dir = f"{option.test_dir}/python"

    assert "success" in client.conf(
        {
            "listeners": {
                "*:8080": {"pass": "applications/python-app-factory"},
                "*:8081": {"pass": "applications/python-app"},
            },
            "applications": {
                "python-app-factory": {
                    "type": client.get_application_type(),
                    "working_directory": f"{python_dir}/factory/",
                    "path": f"{python_dir}/factory/",
                    "module": "wsgi",
                    "callable": "wsgi_a_factory",
                    "factory": True,
                },
                "python-app": {
                    "type": client.get_application_type(),
                    "working_directory": f"{python_dir}/factory/",
                    "path": f"{python_dir}/factory/",
                    "module": "wsgi",
                    "callable": "wsgi_b",
                    "factory": False,
                },
            },
        }
    )

    resp = client.get(port=8080)
    assert resp["status"] == 200
    assert resp["body"] == "1"

    resp = client.get(port=8081)
    assert resp["status"] == 200
    assert resp["body"] == "2"


def test_python_factory_invalid_callable_value(skip_alert):
    skip_alert(
        r"failed to apply new conf",
        r"did not return callable object",
        r"can not be called to fetch callable",
    )
    python_dir = f"{option.test_dir}/python"

    invalid_callable_values = [
        "wsgi_factory_returning_invalid_callable",
        "wsgi_invalid_callable",
    ]

    for callable_value in invalid_callable_values:
        assert "error" in client.conf(
            {
                "listeners": {"*:8080": {"pass": "applications/targets/1"}},
                "applications": {
                    "targets": {
                        "type": client.get_application_type(),
                        "working_directory": f"{python_dir}/factory/",
                        "path": f"{python_dir}/factory/",
                        "targets": {
                            "1": {
                                "module": "wsgi",
                                "callable": callable_value,
                                "factory": True,
                            },
                        },
                    }
                },
            }
        )
