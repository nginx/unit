from unit.applications.lang.go import TestApplicationGo

class TestIsolation(TestApplicationGo):
    prerequisites = ['go']

    def test_detect_isolation_allowed(self):
        isolation = {
            "namespaces": {
                "user": True,
                "pid": True
            }
        }

        self.load('ns_inspect', isolation=isolation)

        body = self.get()['body']
        self.assertIn('"PID":1}', body, "pid 1 not found")

