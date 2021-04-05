from unit.applications.proto import TestApplicationProto


class TestVariables(TestApplicationProto):
    prerequisites = {}

    def setup_method(self):
        assert 'success' in self.conf(
            {
                "listeners": {"*:7080": {"pass": "routes/$method"}},
                "routes": {
                    "GET": [{"action": {"return": 201}}],
                    "POST": [{"action": {"return": 202}}],
                    "3": [{"action": {"return": 203}}],
                    "4*": [{"action": {"return": 204}}],
                    "blahGET}": [{"action": {"return": 205}}],
                    "5GET": [{"action": {"return": 206}}],
                    "GETGET": [{"action": {"return": 207}}],
                    "localhost": [{"action": {"return": 208}}],
                },
            },
        ), 'configure routes'

    def conf_routes(self, routes):
        assert 'success' in self.conf(routes, 'listeners/*:7080/pass')

    def test_variables_method(self):
        assert self.get()['status'] == 201, 'method GET'
        assert self.post()['status'] == 202, 'method POST'

    def test_variables_uri(self):
        self.conf_routes("\"routes$uri\"")

        assert self.get(url='/3')['status'] == 203, 'uri'
        assert self.get(url='/4*')['status'] == 204, 'uri 2'
        assert self.get(url='/4%2A')['status'] == 204, 'uri 3'

    def test_variables_host(self):
        self.conf_routes("\"routes/$host\"")

        def check_host(host, status=208):
            assert (
                self.get(headers={'Host': host, 'Connection': 'close'})[
                    'status'
                ]
                == status
            )

        check_host('localhost')
        check_host('localhost.')
        check_host('localhost:7080')
        check_host('.localhost', 404)
        check_host('www.localhost', 404)
        check_host('localhost1', 404)

    def test_variables_many(self):
        self.conf_routes("\"routes$uri$method\"")
        assert self.get(url='/5')['status'] == 206, 'many'

        self.conf_routes("\"routes${uri}${method}\"")
        assert self.get(url='/5')['status'] == 206, 'many 2'

        self.conf_routes("\"routes${uri}$method\"")
        assert self.get(url='/5')['status'] == 206, 'many 3'

        self.conf_routes("\"routes/$method$method\"")
        assert self.get()['status'] == 207, 'many 4'

        self.conf_routes("\"routes/$method$uri\"")
        assert self.get()['status'] == 404, 'no route'
        assert self.get(url='/blah')['status'] == 404, 'no route 2'

    def test_variables_replace(self):
        assert self.get()['status'] == 201

        self.conf_routes("\"routes$uri\"")
        assert self.get(url='/3')['status'] == 203

        self.conf_routes("\"routes/${method}\"")
        assert self.post()['status'] == 202

        self.conf_routes("\"routes${uri}\"")
        assert self.get(url='/4*')['status'] == 204

        self.conf_routes("\"routes/blah$method}\"")
        assert self.get()['status'] == 205

    def test_variables_upstream(self):
        assert 'success' in self.conf(
            {
                "listeners": {
                    "*:7080": {"pass": "upstreams$uri"},
                    "*:7081": {"pass": "routes/one"},
                },
                "upstreams": {"1": {"servers": {"127.0.0.1:7081": {}}}},
                "routes": {"one": [{"action": {"return": 200}}]},
            },
        ), 'upstreams initial configuration'

        assert self.get(url='/1')['status'] == 200
        assert self.get(url='/2')['status'] == 404

    def test_variables_invalid(self):
        def check_variables(routes):
            assert 'error' in self.conf(
                routes, 'listeners/*:7080/pass'
            ), 'invalid variables'

        check_variables("\"routes$\"")
        check_variables("\"routes${\"")
        check_variables("\"routes${}\"")
        check_variables("\"routes$ur\"")
        check_variables("\"routes$uriblah\"")
        check_variables("\"routes${uri\"")
        check_variables("\"routes${{uri}\"")
