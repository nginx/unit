import os
import re
import unittest
from unit.applications.lang.python import TestApplicationPython


class TestUpstreamsRR(TestApplicationPython):
    prerequisites = {'modules': ['python']}

    def setUp(self):
        super().setUp()

        self.assertIn(
            'success',
            self.conf(
                {
                    "listeners": {
                        "*:7080": {"pass": "upstreams/one"},
                        "*:7081": {"pass": "applications/ups_0"},
                        "*:7082": {"pass": "applications/ups_1"},
                        "*:7083": {"pass": "applications/ups_2"},
                        "*:7090": {"pass": "upstreams/two"},
                    },
                    "upstreams": {
                        "one": {
                            "servers": {
                                "127.0.0.1:7081": {},
                                "127.0.0.1:7082": {},
                            },
                        },
                        "two": {
                            "servers": {
                                "127.0.0.1:7081": {},
                                "127.0.0.1:7082": {},
                            },
                        },
                    },
                    "applications": {
                        "ups_0": {
                            "type": "python",
                            "processes": {"spare": 0},
                            "path": self.current_dir + "/python/upstreams/0",
                            "working_directory": self.current_dir
                            + "/python/upstreams/0",
                            "module": "wsgi",
                        },
                        "ups_1": {
                            "type": "python",
                            "processes": {"spare": 0},
                            "path": self.current_dir + "/python/upstreams/1",
                            "working_directory": self.current_dir
                            + "/python/upstreams/1",
                            "module": "wsgi",
                        },
                        "ups_2": {
                            "type": "python",
                            "processes": {"spare": 0},
                            "path": self.current_dir + "/python/upstreams/2",
                            "working_directory": self.current_dir
                            + "/python/upstreams/2",
                            "module": "wsgi",
                        },
                    },
                },
            ),
            'upstreams initial configuration',
        )

        self.cpu_count = os.cpu_count()

    def get_resps(self, req=100, port=7080):
        resps = [0]
        for _ in range(req):
            headers = self.get(port=port)['headers']
            if 'X-Upstream' in headers:
                ups = int(headers['X-Upstream'])

                if ups > len(resps) - 1:
                    resps.extend([0] * (ups - len(resps) + 1))

                resps[ups] += 1

        return resps

    def get_resps_sc(self, req=100, port=7080):
        to_send = b"""GET / HTTP/1.1
Host: localhost

""" * (
            req - 1
        )

        to_send += b"""GET / HTTP/1.1
Host: localhost
Connection: close

"""

        resp = self.http(to_send, raw_resp=True, raw=True, port=port)
        ups = re.findall('X-Upstream: (\d+)', resp)
        resps = [0] * (int(max(ups)) + 1)

        for i in range(len(ups)):
            resps[int(ups[i])] += 1

        return resps

    def test_upstreams_rr_no_weight(self):
        resps = self.get_resps()
        self.assertLessEqual(
            abs(resps[0] - resps[1]), self.cpu_count, 'no weight'
        )

        self.assertIn(
            'success',
            self.conf_delete('upstreams/one/servers/127.0.0.1:7081'),
            'no weight server remove',
        )

        resps = self.get_resps(req=50)
        self.assertEqual(resps[1], 50, 'no weight 2')

        self.assertIn(
            'success',
            self.conf({}, 'upstreams/one/servers/127.0.0.1:7081'),
            'no weight server revert',
        )

        resps = self.get_resps()
        self.assertLessEqual(
            abs(resps[0] - resps[1]), self.cpu_count, 'no weight 3'
        )

        self.assertIn(
            'success',
            self.conf({}, 'upstreams/one/servers/127.0.0.1:7083'),
            'no weight server new',
        )

        resps = self.get_resps()
        self.assertLessEqual(
            max(resps) - min(resps), self.cpu_count, 'no weight 4'
        )

        resps = self.get_resps_sc(req=30)
        self.assertEqual(resps[0], 10, 'no weight 4 0')
        self.assertEqual(resps[1], 10, 'no weight 4 1')
        self.assertEqual(resps[2], 10, 'no weight 4 2')

    def test_upstreams_rr_weight(self):
        self.assertIn(
            'success',
            self.conf({"weight": 3}, 'upstreams/one/servers/127.0.0.1:7081'),
            'configure weight',
        )

        resps = self.get_resps_sc()
        self.assertEqual(resps[0], 75, 'weight 3 0')
        self.assertEqual(resps[1], 25, 'weight 3 1')

        self.assertIn(
            'success',
            self.conf_delete('upstreams/one/servers/127.0.0.1:7081/weight'),
            'configure weight remove',
        )
        resps = self.get_resps_sc(req=10)
        self.assertEqual(resps[0], 5, 'weight 0 0')
        self.assertEqual(resps[1], 5, 'weight 0 1')

        self.assertIn(
            'success',
            self.conf('1', 'upstreams/one/servers/127.0.0.1:7081/weight'),
            'configure weight 1',
        )

        resps = self.get_resps_sc()
        self.assertEqual(resps[0], 50, 'weight 1 0')
        self.assertEqual(resps[1], 50, 'weight 1 1')

        self.assertIn(
            'success',
            self.conf(
                {
                    "127.0.0.1:7081": {"weight": 3},
                    "127.0.0.1:7083": {"weight": 2},
                },
                'upstreams/one/servers',
            ),
            'configure weight 2',
        )

        resps = self.get_resps_sc()
        self.assertEqual(resps[0], 60, 'weight 2 0')
        self.assertEqual(resps[2], 40, 'weight 2 1')

    def test_upstreams_rr_weight_rational(self):
        def set_weights(w1, w2):
            self.assertIn(
                'success',
                self.conf(
                    {
                        "127.0.0.1:7081": {"weight": w1},
                        "127.0.0.1:7082": {"weight": w2},
                    },
                    'upstreams/one/servers',
                ),
                'configure weights',
            )

        def check_reqs(w1, w2, reqs=10):
            resps = self.get_resps_sc(req=reqs)
            self.assertEqual(resps[0], reqs * w1 / (w1 + w2), 'weight 1')
            self.assertEqual(resps[1], reqs * w2 / (w1 + w2), 'weight 2')

        def check_weights(w1, w2):
            set_weights(w1, w2)
            check_reqs(w1, w2)

        check_weights(0, 1)
        check_weights(0, 999999.0123456)
        check_weights(1, 9)
        check_weights(100000, 900000)
        check_weights(1, .25)
        check_weights(1, 0.25)
        check_weights(0.2, .8)
        check_weights(1, 1.5)
        check_weights(1e-3, 1E-3)
        check_weights(1e-20, 1e-20)
        check_weights(1e4, 1e4)
        check_weights(1000000, 1000000)

        set_weights(0.25, 0.25)
        self.assertIn(
            'success',
            self.conf_delete('upstreams/one/servers/127.0.0.1:7081/weight'),
            'delete weight',
        )
        check_reqs(1, 0.25)

        self.assertIn(
            'success',
            self.conf(
                {
                    "127.0.0.1:7081": {"weight": 0.1},
                    "127.0.0.1:7082": {"weight": 1},
                    "127.0.0.1:7083": {"weight": 0.9},
                },
                'upstreams/one/servers',
            ),
            'configure weights',
        )
        resps = self.get_resps_sc(req=20)
        self.assertEqual(resps[0], 1, 'weight 3 1')
        self.assertEqual(resps[1], 10, 'weight 3 2')
        self.assertEqual(resps[2], 9, 'weight 3 3')

    def test_upstreams_rr_independent(self):
        def sum_resps(*args):
            sum = [0] * len(args[0])
            for arg in args:
                sum = [x + y for x, y in zip(sum, arg)]

            return sum

        resps = self.get_resps_sc(req=30, port=7090)
        self.assertEqual(resps[0], 15, 'dep two before 0')
        self.assertEqual(resps[1], 15, 'dep two before 1')

        resps = self.get_resps_sc(req=30)
        self.assertEqual(resps[0], 15, 'dep one before 0')
        self.assertEqual(resps[1], 15, 'dep one before 1')

        self.assertIn(
            'success',
            self.conf('2', 'upstreams/two/servers/127.0.0.1:7081/weight'),
            'configure dep weight',
        )

        resps = self.get_resps_sc(req=30, port=7090)
        self.assertEqual(resps[0], 20, 'dep two 0')
        self.assertEqual(resps[1], 10, 'dep two 1')

        resps = self.get_resps_sc(req=30)
        self.assertEqual(resps[0], 15, 'dep one 0')
        self.assertEqual(resps[1], 15, 'dep one 1')

        self.assertIn(
            'success',
            self.conf('1', 'upstreams/two/servers/127.0.0.1:7081/weight'),
            'configure dep weight 1',
        )

        r_one, r_two = [0, 0], [0, 0]
        for _ in range(10):
            r_one = sum_resps(r_one, self.get_resps(req=10))
            r_two = sum_resps(r_two, self.get_resps(req=10, port=7090))

        self.assertLessEqual(
            abs(r_one[0] - r_one[1]), self.cpu_count, 'dep one mix'
        )
        self.assertLessEqual(
            abs(r_two[0] - r_two[1]), self.cpu_count, 'dep two mix'
        )

    def test_upstreams_rr_delay(self):
        headers_delay_1 = {
            'Connection': 'close',
            'Host': 'localhost',
            'Content-Length': '0',
            'X-Delay': '1',
        }
        headers_no_delay = {
            'Connection': 'close',
            'Host': 'localhost',
            'Content-Length': '0',
        }

        req = 50

        socks = []
        for i in range(req):
            headers = headers_delay_1 if i % 5 == 0 else headers_no_delay
            _, sock = self.get(
                headers=headers,
                start=True,
                no_recv=True,
            )
            socks.append(sock)

        resps = [0, 0]
        for i in range(req):
            resp = self.recvall(socks[i]).decode()
            socks[i].close()

            m = re.search('X-Upstream: (\d+)', resp)
            resps[int(m.group(1))] += 1

        self.assertLessEqual(
            abs(resps[0] - resps[1]), self.cpu_count, 'dep two mix'
        )

    def test_upstreams_rr_active_req(self):
        conns = 5
        socks = []
        socks2 = []

        for _ in range(conns):
            _, sock = self.get(start=True, no_recv=True)
            socks.append(sock)

            _, sock2 = self.http(
                b"""POST / HTTP/1.1
Host: localhost
Content-Length: 10
Connection: close

""",
                start=True,
                no_recv=True,
                raw=True,
            )
            socks2.append(sock2)

        # Send one more request and read response to make sure that previous
        # requests had enough time to reach server.

        self.assertEqual(self.get()['status'], 200)

        self.assertIn(
            'success',
            self.conf(
                {"127.0.0.1:7083": {"weight": 2}}, 'upstreams/one/servers',
            ),
            'active req new server',
        )
        self.assertIn(
            'success',
            self.conf_delete('upstreams/one/servers/127.0.0.1:7083'),
            'active req server remove',
        )
        self.assertIn(
            'success', self.conf_delete('listeners/*:7080'), 'delete listener'
        )
        self.assertIn(
            'success',
            self.conf_delete('upstreams/one'),
            'active req upstream remove',
        )

        for i in range(conns):
            resp = self.recvall(socks[i]).decode()
            socks[i].close()

            self.assertRegex(resp, r'X-Upstream', 'active req GET')

            resp = self.http(b"""0123456789""", sock=socks2[i], raw=True)
            self.assertEqual(resp['status'], 200, 'active req POST')

    def test_upstreams_rr_bad_server(self):
        self.assertIn(
            'success',
            self.conf({"weight": 1}, 'upstreams/one/servers/127.0.0.1:7084'),
            'configure bad server',
        )

        resps = self.get_resps_sc(req=30)
        self.assertEqual(resps[0], 10, 'bad server 0')
        self.assertEqual(resps[1], 10, 'bad server 1')
        self.assertEqual(sum(resps), 20, 'bad server sum')

    def test_upstreams_rr_pipeline(self):
        resps = self.get_resps_sc()

        self.assertEqual(resps[0], 50, 'pipeline 0')
        self.assertEqual(resps[1], 50, 'pipeline 1')

    def test_upstreams_rr_post(self):
        resps = [0, 0]
        for _ in range(50):
            resps[
                int(self.post(body='0123456789')['headers']['X-Upstream'])
            ] += 1
            resps[int(self.get()['headers']['X-Upstream'])] += 1

        self.assertLessEqual(
            abs(resps[0] - resps[1]), self.cpu_count, 'post'
        )

    def test_upstreams_rr_unix(self):
        addr_0 = self.testdir + '/sock_0'
        addr_1 = self.testdir + '/sock_1'

        self.assertIn(
            'success',
            self.conf(
                {
                    "*:7080": {"pass": "upstreams/one"},
                    "unix:" + addr_0: {"pass": "applications/ups_0"},
                    "unix:" + addr_1: {"pass": "applications/ups_1"},
                },
                'listeners',
            ),
            'configure listeners unix',
        )

        self.assertIn(
            'success',
            self.conf(
                {"unix:" + addr_0: {}, "unix:" + addr_1: {},},
                'upstreams/one/servers',
            ),
            'configure servers unix',
        )

        resps = self.get_resps_sc()

        self.assertEqual(resps[0], 50, 'unix 0')
        self.assertEqual(resps[1], 50, 'unix 1')

    def test_upstreams_rr_ipv6(self):
        self.assertIn(
            'success',
            self.conf(
                {
                    "*:7080": {"pass": "upstreams/one"},
                    "[::1]:7081": {"pass": "applications/ups_0"},
                    "[::1]:7082": {"pass": "applications/ups_1"},
                },
                'listeners',
            ),
            'configure listeners ipv6',
        )

        self.assertIn(
            'success',
            self.conf(
                {"[::1]:7081": {}, "[::1]:7082": {},}, 'upstreams/one/servers'
            ),
            'configure servers ipv6',
        )

        resps = self.get_resps_sc()

        self.assertEqual(resps[0], 50, 'ipv6 0')
        self.assertEqual(resps[1], 50, 'ipv6 1')

    def test_upstreams_rr_servers_empty(self):
        self.assertIn(
            'success',
            self.conf({}, 'upstreams/one/servers'),
            'configure servers empty',
        )
        self.assertEqual(self.get()['status'], 502, 'servers empty')

        self.assertIn(
            'success',
            self.conf(
                {"127.0.0.1:7081": {"weight": 0}}, 'upstreams/one/servers'
            ),
            'configure servers empty one',
        )
        self.assertEqual(self.get()['status'], 502, 'servers empty one')
        self.assertIn(
            'success',
            self.conf(
                {
                    "127.0.0.1:7081": {"weight": 0},
                    "127.0.0.1:7082": {"weight": 0},
                },
                'upstreams/one/servers',
            ),
            'configure servers empty two',
        )
        self.assertEqual(self.get()['status'], 502, 'servers empty two')

    def test_upstreams_rr_invalid(self):
        self.assertIn(
            'error', self.conf({}, 'upstreams'), 'upstreams empty',
        )
        self.assertIn(
            'error', self.conf({}, 'upstreams/one'), 'named upstreams empty',
        )
        self.assertIn(
            'error',
            self.conf({}, 'upstreams/one/servers/127.0.0.1'),
            'invalid address',
        )
        self.assertIn(
            'error',
            self.conf({}, 'upstreams/one/servers/127.0.0.1:7081/blah'),
            'invalid server option',
        )

        def check_weight(w):
            self.assertIn(
                'error',
                self.conf(w, 'upstreams/one/servers/127.0.0.1:7081/weight'),
                'invalid weight option',
            )
        check_weight({})
        check_weight('-1')
        check_weight('1.')
        check_weight('1.1.')
        check_weight('.')
        check_weight('.01234567890123')
        check_weight('1000001')
        check_weight('2e6')


if __name__ == '__main__':
    TestUpstreamsRR.main()
