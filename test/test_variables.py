from unit.applications.proto import TestApplicationProto


class TestVariables(TestApplicationProto):
    prerequisites = {}

    def setUp(self):
        super().setUp()

        self.assertIn(
            'success',
            self.conf(
                {
                    "listeners": {"*:7080": {"pass": "routes/$method"}},
                    "routes": {
                        "GET": [{"action": {"return": 201}}],
                        "POST": [{"action": {"return": 202}}],
                        "3": [{"action": {"return": 203}}],
                        "4": [{"action": {"return": 204}}],
                        "blahGET}": [{"action": {"return": 205}}],
                        "5GET": [{"action": {"return": 206}}],
                        "GETGET": [{"action": {"return": 207}}],
                    },
                },
            ),
            'configure routes',
        )

    def conf_routes(self, routes):
        self.assertIn(
            'success',
            self.conf(routes, 'listeners/*:7080/pass')
        )

    def test_variables_method(self):
        self.assertEqual(self.get()['status'], 201, 'method GET')
        self.assertEqual(self.post()['status'], 202, 'method POST')

    def test_variables_uri(self):
        self.conf_routes("\"routes$uri\"")

        self.assertEqual(self.get(url='/3')['status'], 203, 'uri')
        self.assertEqual(self.get(url='/4')['status'], 204, 'uri 2')

    def test_variables_many(self):
        self.conf_routes("\"routes$uri$method\"")
        self.assertEqual(self.get(url='/5')['status'], 206, 'many')

        self.conf_routes("\"routes${uri}${method}\"")
        self.assertEqual(self.get(url='/5')['status'], 206, 'many 2')

        self.conf_routes("\"routes${uri}$method\"")
        self.assertEqual(self.get(url='/5')['status'], 206, 'many 3')

        self.conf_routes("\"routes/$method$method\"")
        self.assertEqual(self.get()['status'], 207, 'many 4')

        self.conf_routes("\"routes/$method$uri\"")
        self.assertEqual(self.get()['status'], 404, 'no route')
        self.assertEqual(self.get(url='/blah')['status'], 404, 'no route 2')

    def test_variables_replace(self):
        self.assertEqual(self.get()['status'], 201)

        self.conf_routes("\"routes$uri\"")
        self.assertEqual(self.get(url='/3')['status'], 203)

        self.conf_routes("\"routes/${method}\"")
        self.assertEqual(self.post()['status'], 202)

        self.conf_routes("\"routes${uri}\"")
        self.assertEqual(self.get(url='/4')['status'], 204)

        self.conf_routes("\"routes/blah$method}\"")
        self.assertEqual(self.get()['status'], 205)

    def test_variables_invalid(self):
        def check_variables(routes):
            self.assertIn(
                'error',
                self.conf(routes, 'listeners/*:7080/pass'),
                'invalid variables',
            )

        check_variables("\"routes$\"")
        check_variables("\"routes${\"")
        check_variables("\"routes${}\"")
        check_variables("\"routes$ur\"")
        check_variables("\"routes$uriblah\"")
        check_variables("\"routes${uri\"")
        check_variables("\"routes${{uri}\"")

if __name__ == '__main__':
    TestVariables.main()
