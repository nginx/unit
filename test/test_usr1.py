import os
import unittest
from subprocess import call
from unit.applications.lang.python import TestApplicationPython


class TestUSR1(TestApplicationPython):
    prerequisites = {'modules': ['python']}

    def test_usr1_access_log(self):
        self.load('empty')

        log_path = self.testdir + '/access.log'

        self.assertIn(
            'success',
            self.conf('"' + log_path + '"', 'access_log'),
            'access log configure',
        )

        self.assertTrue(self.waitforfiles(log_path), 'open')

        log_path_new = self.testdir + '/new.log'

        os.rename(log_path, log_path_new)

        self.get()

        self.assertIsNotNone(
            self.wait_for_record(r'"GET / HTTP/1.1" 200 0 "-" "-"', 'new.log'),
            'rename new',
        )
        self.assertFalse(os.path.isfile(log_path), 'rename old')

        with open(self.testdir + '/unit.pid', 'r') as f:
            pid = f.read().rstrip()

        call(['kill', '-s', 'USR1', pid])

        self.assertTrue(self.waitforfiles(log_path), 'reopen')

        self.get(url='/usr1')

        self.assertIsNotNone(
            self.wait_for_record(
                r'"GET /usr1 HTTP/1.1" 200 0 "-" "-"', 'access.log'
            ),
            'reopen 2',
        )
        self.assertIsNone(
            self.search_in_log(r'/usr1', 'new.log'), 'rename new 2'
        )

    @unittest.skip('not yet')
    def test_usr1_unit_log(self):
        self.load('log_body')

        log_path = self.testdir + '/unit.log'
        log_path_new = self.testdir + '/new.log'

        os.rename(log_path, log_path_new)

        body = 'body_for_a_log_new'
        self.post(body=body)

        self.assertIsNotNone(
            self.wait_for_record(body, 'new.log'), 'rename new'
        )
        self.assertFalse(os.path.isfile(log_path), 'rename old')

        with open(self.testdir + '/unit.pid', 'r') as f:
            pid = f.read().rstrip()

        call(['kill', '-s', 'USR1', pid])

        self.assertTrue(self.waitforfiles(log_path), 'reopen')

        body = 'body_for_a_log_unit'
        self.post(body=body)

        self.assertIsNotNone(self.wait_for_record(body), 'rename new')
        self.assertIsNone(self.search_in_log(body, 'new.log'), 'rename new 2')

        # merge two log files into unit.log to check alerts

        with open(log_path,     'w') as unit_log, \
             open(log_path_new, 'r') as new_log:
            unit_log.write(new_log.read())


if __name__ == '__main__':
    TestUSR1.main()
