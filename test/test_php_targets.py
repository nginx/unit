from unit.applications.lang.php import TestApplicationPHP

class TestPHPTargets(TestApplicationPHP):
    prerequisites = {'modules': {'php': 'any'}}

    def test_php_application_targets(self):
        self.assertIn(
            'success',
            self.conf(
                {
                    "listeners": {"*:7080": {"pass": "routes"}},
                    "routes": [
                        {
                            "match": {"uri": "/1"},
                            "action": {"pass": "applications/targets/1"},
                        },
                        {
                            "match": {"uri": "/2"},
                            "action": {"pass": "applications/targets/2"},
                        },
                        {"action": {"pass": "applications/targets/default"}},
                    ],
                    "applications": {
                        "targets": {
                            "type": "php",
                            "processes": {"spare": 0},
                            "targets": {
                                "1": {
                                    "script": "1.php",
                                    "root": self.current_dir + "/php/targets",
                                },
                                "2": {
                                    "script": "2.php",
                                    "root": self.current_dir
                                    + "/php/targets/2",
                                },
                                "default": {
                                    "index": "index.php",
                                    "root": self.current_dir + "/php/targets",
                                },
                            },
                        }
                    },
                }
            ),
        )

        self.assertEqual(self.get(url='/1')['body'], '1')
        self.assertEqual(self.get(url='/2')['body'], '2')
        self.assertEqual(self.get(url='/blah')['status'], 503)  # TODO 404
        self.assertEqual(self.get(url='/')['body'], 'index')

        self.assertIn(
            'success',
            self.conf(
                "\"1.php\"", 'applications/targets/targets/default/index'
            ),
            'change targets index',
        )
        self.assertEqual(self.get(url='/')['body'], '1')

        self.assertIn(
            'success',
            self.conf_delete('applications/targets/targets/default/index'),
            'remove targets index',
        )
        self.assertEqual(self.get(url='/')['body'], 'index')

    def test_php_application_targets_error(self):
        self.assertIn(
            'success',
            self.conf(
                {
                    "listeners": {
                        "*:7080": {"pass": "applications/targets/default"}
                    },
                    "applications": {
                        "targets": {
                            "type": "php",
                            "processes": {"spare": 0},
                            "targets": {
                                "default": {
                                    "index": "index.php",
                                    "root": self.current_dir + "/php/targets",
                                },
                            },
                        }
                    },
                }
            ),
            'initial configuration',
        )
        self.assertEqual(self.get()['status'], 200)

        self.assertIn(
            'error',
            self.conf(
                {"pass": "applications/targets/blah"}, 'listeners/*:7080'
            ),
            'invalid targets pass',
        )
        self.assertIn(
            'error',
            self.conf(
                '"' + self.current_dir + '/php/targets\"',
                'applications/targets/root',
            ),
            'invalid root',
        )
        self.assertIn(
            'error',
            self.conf('"index.php"', 'applications/targets/index'),
            'invalid index',
        )
        self.assertIn(
            'error',
            self.conf('"index.php"', 'applications/targets/script'),
            'invalid script',
        )
        self.assertIn(
            'error',
            self.conf_delete('applications/targets/default/root'),
            'root remove',
        )


if __name__ == '__main__':
    TestPHPTargets.main()
