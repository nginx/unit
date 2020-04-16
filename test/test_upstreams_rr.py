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
                        "*:7090": {"pass": "upstreams/two"},
                        "*:7081": {"pass": "routes/one"},
                        "*:7082": {"pass": "routes/two"},
                        "*:7083": {"pass": "routes/three"},
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
                    "routes": {
                        "one": [{"action": {"return": 200}}],
                        "two": [{"action": {"return": 201}}],
                        "three": [{"action": {"return": 202}}],
                    },
                    "applications": {},
                },
            ),
            'upstreams initial configuration',
        )

        self.cpu_count = os.cpu_count()

    def get_resps(self, req=100, port=7080):
        resps = [0]

        for _ in range(req):
            status = self.get(port=port)['status']
            if 200 > status or status > 209:
                continue

            ups = status % 10
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
        status = re.findall(r'HTTP\/\d\.\d\s(\d\d\d)', resp)
        status = list(filter(lambda x: x[:2] == '20', status))
        ups = list(map(lambda x: int(x[-1]), status))

        resps = [0] * (max(ups) + 1)
        for i in range(len(ups)):
            resps[ups[i]] += 1

        return resps

    def test_upstreams_rr_no_weight(self):
        resps = self.get_resps()
        self.assertEqual(sum(resps), 100, 'no weight sum')
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
        self.assertEqual(sum(resps), 100, 'no weight 3 sum')
        self.assertLessEqual(
            abs(resps[0] - resps[1]), self.cpu_count, 'no weight 3'
        )

        self.assertIn(
            'success',
            self.conf({}, 'upstreams/one/servers/127.0.0.1:7083'),
            'no weight server new',
        )

        resps = self.get_resps()
        self.assertEqual(sum(resps), 100, 'no weight 4 sum')
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


        self.assertEqual(sum(r_one), 100, 'dep one mix sum')
        self.assertLessEqual(
            abs(r_one[0] - r_one[1]), self.cpu_count, 'dep one mix'
        )
        self.assertEqual(sum(r_two), 100, 'dep two mix sum')
        self.assertLessEqual(
            abs(r_two[0] - r_two[1]), self.cpu_count, 'dep two mix'
        )

    def test_upstreams_rr_delay(self):
        self.assertIn(
            'success',
            self.conf(
                {
                    "listeners": {
                        "*:7080": {"pass": "upstreams/one"},
                        "*:7081": {"pass": "routes"},
                        "*:7082": {"pass": "routes"},
                    },
                    "upstreams": {
                        "one": {
                            "servers": {
                                "127.0.0.1:7081": {},
                                "127.0.0.1:7082": {},
                            },
                        },
                    },
                    "routes": [
                        {
                            "match": {"destination": "*:7081"},
                            "action": {"pass": "applications/delayed"},
                        },
                        {
                            "match": {"destination": "*:7082"},
                            "action": {"return": 201},
                        },
                    ],
                    "applications": {
                        "delayed": {
                            "type": "python",
                            "processes": {"spare": 0},
                            "path": self.current_dir + "/python/delayed",
                            "working_directory": self.current_dir
                            + "/python/delayed",
                            "module": "wsgi",
                        }
                    },
                },
            ),
            'upstreams initial configuration',
        )

        req = 50

        socks = []
        for i in range(req):
            delay = 1 if i % 5 == 0 else 0
            _, sock = self.get(
                headers={
                    'Host': 'localhost',
                    'Content-Length': '0',
                    'X-Delay': str(delay),
                    'Connection': 'close',
                },
                start=True,
                no_recv=True,
            )
            socks.append(sock)

        resps = [0, 0]
        for i in range(req):
            resp = self.recvall(socks[i]).decode()
            socks[i].close()

            m = re.search('HTTP/1.1 20(\d)', resp)
            self.assertIsNotNone(m, 'status')
            resps[int(m.group(1))] += 1

        self.assertEqual(sum(resps), req, 'delay sum')
        self.assertLessEqual(abs(resps[0] - resps[1]), self.cpu_count, 'delay')

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

        self.assertEqual(self.get()['body'], '')

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
            self.assertEqual(
                self.http(b'', sock=socks[i], raw=True)['body'],
                '',
                'active req GET',
            )

            self.assertEqual(
                self.http(b"""0123456789""", sock=socks2[i], raw=True)['body'],
                '',
                'active req POST',
            )

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
            resps[self.get()['status'] % 10] += 1
            resps[self.post(body='0123456789')['status'] % 10] += 1

        self.assertEqual(sum(resps), 100, 'post sum')
        self.assertLessEqual(abs(resps[0] - resps[1]), self.cpu_count, 'post')

    def test_upstreams_rr_unix(self):
        addr_0 = self.testdir + '/sock_0'
        addr_1 = self.testdir + '/sock_1'

        self.assertIn(
            'success',
            self.conf(
                {
                    "*:7080": {"pass": "upstreams/one"},
                    "unix:" + addr_0: {"pass": "routes/one"},
                    "unix:" + addr_1: {"pass": "routes/two"},
                },
                'listeners',
            ),
            'configure listeners unix',
        )

        self.assertIn(
            'success',
            self.conf(
                {"unix:" + addr_0: {}, "unix:" + addr_1: {}},
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
                    "[::1]:7081": {"pass": "routes/one"},
                    "[::1]:7082": {"pass": "routes/two"},
                },
                'listeners',
            ),
            'configure listeners ipv6',
        )

        self.assertIn(
            'success',
            self.conf(
                {"[::1]:7081": {}, "[::1]:7082": {}}, 'upstreams/one/servers'
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
