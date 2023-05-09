import os

import pytest
from unit.applications.proto import TestApplicationProto
from unit.option import option


class TestRewrite(TestApplicationProto):
    prerequisites = {}

    def setup_method(self):
        assert 'success' in self.conf(
            {
                "listeners": {"*:7080": {"pass": "routes"}},
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

    def set_rewrite(self, rewrite, uri):
        assert 'success' in self.conf(
            [
                {
                    "match": {"uri": "/"},
                    "action": {"rewrite": rewrite, "pass": "routes"},
                },
                {"match": {"uri": uri}, "action": {"return": 200}},
            ],
            'routes',
        )

    def test_rewrite(self):
        assert self.get()['status'] == 200
        assert (
            self.wait_for_record(rf'\[notice\].*"routes/1" selected')
            is not None
        )
        assert len(self.findall(rf'\[notice\].*URI rewritten to "/new"')) == 1
        assert len(self.findall(rf'\[notice\].*URI rewritten')) == 1

        self.set_rewrite("", "")
        assert self.get()['status'] == 200

    def test_rewrite_variable(self):
        self.set_rewrite("/$host", "/localhost")
        assert self.get()['status'] == 200

        self.set_rewrite("${uri}a", "/a")
        assert self.get()['status'] == 200

    def test_rewrite_encoded(self):
        assert 'success' in self.conf(
            [
                {
                    "match": {"uri": "/f"},
                    "action": {"rewrite": "${request_uri}oo", "pass": "routes"},
                },
                {"match": {"uri": "/foo"}, "action": {"return": 200}},
            ],
            'routes',
        )
        assert self.get(url='/%66')['status'] == 200

        assert 'success' in self.conf(
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
        assert self.get(url='/%66')['status'] == 200

    def test_rewrite_arguments(self):
        assert 'success' in self.conf(
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
        assert self.get(url='/foo?arg=val')['status'] == 200

    def test_rewrite_njs(self):
        if 'njs' not in option.available['modules'].keys():
            pytest.skip('NJS is not available')

        self.set_rewrite("`/${host}`", "/localhost")
        assert self.get()['status'] == 200

    def test_rewrite_location(self):
        def check_location(rewrite, expect):
            assert 'success' in self.conf(
                {
                    "listeners": {"*:7080": {"pass": "routes"}},
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
            assert self.get()['headers']['Location'] == expect

        check_location('/new', '/new')
        check_location('${request_uri}new', '/new')

    def test_rewrite_share(self, temp_dir):
        os.makedirs(f'{temp_dir}/dir')
        os.makedirs(f'{temp_dir}/foo')

        with open(f'{temp_dir}/foo/index.html', 'w') as fooindex:
            fooindex.write('fooindex')

        # same action block

        assert 'success' in self.conf(
            {
                "listeners": {"*:7080": {"pass": "routes"}},
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

        resp = self.get()
        assert resp['status'] == 301, 'redirect status'
        assert resp['headers']['Location'] == '/dir/', 'redirect Location'

        # request_uri

        index_path = f'{temp_dir}${{request_uri}}/index.html'
        assert 'success' in self.conf(
            {
                "listeners": {"*:7080": {"pass": "routes"}},
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

        assert self.get(url='/foo')['body'] == 'fooindex'

        # different action block

        assert 'success' in self.conf(
            {
                "listeners": {"*:7080": {"pass": "routes"}},
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
        resp = self.get(url='/foo')
        assert resp['status'] == 301, 'redirect status 2'
        assert resp['headers']['Location'] == '/foodir/', 'redirect Location 2'

    def test_rewrite_invalid(self, skip_alert):
        skip_alert(r'failed to apply new conf')

        def check_rewrite(rewrite):
            assert 'error' in self.conf(
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
