import os
from subprocess import call

from unit.applications.lang.python import TestApplicationPython


class TestUSR1(TestApplicationPython):
    prerequisites = {'modules': {'python': 'any'}}

    def test_usr1_access_log(self):
        self.load('empty')

        log = 'access.log'
        log_new = 'new.log'
        log_path = self.testdir + '/' + log

        self.assertIn(
            'success',
            self.conf('"' + log_path + '"', 'access_log'),
            'access log configure',
        )

        self.assertTrue(self.waitforfiles(log_path), 'open')

        os.rename(log_path, self.testdir + '/' + log_new)

        self.assertEqual(self.get()['status'], 200)

        self.assertIsNotNone(
            self.wait_for_record(r'"GET / HTTP/1.1" 200 0 "-" "-"', log_new),
            'rename new',
        )
        self.assertFalse(os.path.isfile(log_path), 'rename old')

        with open(self.testdir + '/unit.pid', 'r') as f:
            pid = f.read().rstrip()

        call(['kill', '-s', 'USR1', pid])

        self.assertTrue(self.waitforfiles(log_path), 'reopen')

        self.assertEqual(self.get(url='/usr1')['status'], 200)

        self.stop()

        self.assertIsNotNone(
            self.wait_for_record(r'"GET /usr1 HTTP/1.1" 200 0 "-" "-"', log),
            'reopen 2',
        )
        self.assertIsNone(
            self.search_in_log(r'/usr1', log_new), 'rename new 2'
        )

    def test_usr1_unit_log(self):
        self.load('log_body')

        log_new = 'new.log'
        log_path = self.testdir + '/unit.log'
        log_path_new = self.testdir + '/' + log_new

        os.rename(log_path, log_path_new)

        body = 'body_for_a_log_new'
        self.assertEqual(self.post(body=body)['status'], 200)

        self.assertIsNotNone(
            self.wait_for_record(body, log_new), 'rename new'
        )
        self.assertFalse(os.path.isfile(log_path), 'rename old')

        with open(self.testdir + '/unit.pid', 'r') as f:
            pid = f.read().rstrip()

        call(['kill', '-s', 'USR1', pid])

        self.assertTrue(self.waitforfiles(log_path), 'reopen')

        body = 'body_for_a_log_unit'
        self.assertEqual(self.post(body=body)['status'], 200)

        self.stop()

        self.assertIsNotNone(self.wait_for_record(body), 'rename new')
        self.assertIsNone(self.search_in_log(body, log_new), 'rename new 2')

        # merge two log files into unit.log to check alerts

        with open(log_path,     'w') as unit_log, \
             open(log_path_new, 'r') as unit_log_new:
            unit_log.write(unit_log_new.read())


if __name__ == '__main__':
    TestUSR1.main()
