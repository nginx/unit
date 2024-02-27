from pathlib import Path

import pytest

from unit.applications.proto import ApplicationProto

client = ApplicationProto()


@pytest.fixture(autouse=True)
def setup_method_fixture():
    assert 'success' in client.conf(
        {
            "listeners": {"*:8080": {"pass": "routes"}},
            "routes": [
                {
                    "match": {"uri": "/"},
                    "action": {"rewrite": "/new", "pass": "routes"},
                },
                {"match": {"uri": "/new"}, "action": {"return": 200}},
            ],
            "applications": {},
            "settings": {"http": {"log_route": True}},
        },
    ), 'set initial configuration'


def set_rewrite(rewrite, uri):
    assert 'success' in client.conf(
        [
            {
                "match": {"uri": "/"},
                "action": {"rewrite": rewrite, "pass": "routes"},
            },
            {"match": {"uri": uri}, "action": {"return": 200}},
        ],
        'routes',
    )


def test_rewrite(findall, wait_for_record):
    assert client.get()['status'] == 200
    assert wait_for_record(r'\[notice\].*"routes/1" selected') is not None
    assert len(findall(r'\[notice\].*URI rewritten to "/new"')) == 1
    assert len(findall(r'\[notice\].*URI rewritten')) == 1

    set_rewrite("", "")
    assert client.get()['status'] == 200


def test_rewrite_variable():
    set_rewrite("/$host", "/localhost")
    assert client.get()['status'] == 200

    set_rewrite("${uri}a", "/a")
    assert client.get()['status'] == 200


def test_rewrite_encoded():
    assert 'success' in client.conf(
        [
            {
                "match": {"uri": "/f"},
                "action": {"rewrite": "${request_uri}oo", "pass": "routes"},
            },
            {"match": {"uri": "/foo"}, "action": {"return": 200}},
        ],
        'routes',
    )
    assert client.get(url='/%66')['status'] == 200

    assert 'success' in client.conf(
        [
            {
                "match": {"uri": "/f"},
                "action": {
                    "rewrite": "${request_uri}o%6F",
                    "pass": "routes",
                },
            },
            {"match": {"uri": "/foo"}, "action": {"return": 200}},
        ],
        'routes',
    )
    assert client.get(url='/%66')['status'] == 200


def test_rewrite_arguments():
    assert 'success' in client.conf(
        [
            {
                "match": {"uri": "/foo", "arguments": {"arg": "val"}},
                "action": {"rewrite": "/new?some", "pass": "routes"},
            },
            {
                "match": {"uri": "/new", "arguments": {"arg": "val"}},
                "action": {"return": 200},
            },
        ],
        'routes',
    )
    assert client.get(url='/foo?arg=val')['status'] == 200


def test_rewrite_njs(require):
    require({'modules': {'njs': 'any'}})

    set_rewrite("`/${host}`", "/localhost")
    assert client.get()['status'] == 200


def test_rewrite_location():
    def check_location(rewrite, expect):
        assert 'success' in client.conf(
            {
                "listeners": {"*:8080": {"pass": "routes"}},
                "routes": [
                    {
                        "action": {
                            "return": 301,
                            "location": "$uri",
                            "rewrite": rewrite,
                        }
                    }
                ],
            }
        )
        assert client.get()['headers']['Location'] == expect

    check_location('/new', '/new')
    check_location('${request_uri}new', '/new')


def test_rewrite_share(temp_dir):
    Path(f'{temp_dir}/dir').mkdir()
    Path(f'{temp_dir}/foo/').mkdir()
    Path(f'{temp_dir}/foo/index.html').write_text('fooindex', encoding='utf-8')

    # same action block

    assert 'success' in client.conf(
        {
            "listeners": {"*:8080": {"pass": "routes"}},
            "routes": [
                {
                    "action": {
                        "rewrite": "${request_uri}dir",
                        "share": f'{temp_dir}$uri',
                    }
                }
            ],
        }
    )

    resp = client.get()
    assert resp['status'] == 301, 'redirect status'
    assert resp['headers']['Location'] == '/dir/', 'redirect Location'

    # request_uri

    index_path = f'{temp_dir}${{request_uri}}/index.html'
    assert 'success' in client.conf(
        {
            "listeners": {"*:8080": {"pass": "routes"}},
            "routes": [
                {
                    "match": {"uri": "/foo"},
                    "action": {
                        "rewrite": "${request_uri}dir",
                        "pass": "routes",
                    },
                },
                {"action": {"share": index_path}},
            ],
        }
    )

    assert client.get(url='/foo')['body'] == 'fooindex'

    # different action block

    assert 'success' in client.conf(
        {
            "listeners": {"*:8080": {"pass": "routes"}},
            "routes": [
                {
                    "match": {"uri": "/foo"},
                    "action": {
                        "rewrite": "${request_uri}dir",
                        "pass": "routes",
                    },
                },
                {
                    "action": {
                        "share": f'{temp_dir}/dir',
                    }
                },
            ],
        }
    )
    resp = client.get(url='/foo')
    assert resp['status'] == 301, 'redirect status 2'
    assert resp['headers']['Location'] == '/foodir/', 'redirect Location 2'


def test_rewrite_invalid(skip_alert):
    skip_alert(r'failed to apply new conf')

    def check_rewrite(rewrite):
        assert 'error' in client.conf(
            [
                {
                    "match": {"uri": "/"},
                    "action": {"rewrite": rewrite, "pass": "routes"},
                },
                {"action": {"return": 200}},
            ],
            'routes',
        )

    check_rewrite("/$blah")
    check_rewrite(["/"])
