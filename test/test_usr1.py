import os
from subprocess import call

from conftest import unit_stop
from unit.applications.lang.python import TestApplicationPython
from unit.utils import waitforfiles


class TestUSR1(TestApplicationPython):
    prerequisites = {'modules': {'python': 'any'}}

    def test_usr1_access_log(self, temp_dir):
        self.load('empty')

        log = 'access.log'
        log_new = 'new.log'
        log_path = temp_dir + '/' + log

        assert 'success' in self.conf(
            '"' + log_path + '"', 'access_log'
        ), 'access log configure'

        assert waitforfiles(log_path), 'open'

        os.rename(log_path, temp_dir + '/' + log_new)

        assert self.get()['status'] == 200

        assert (
            self.wait_for_record(r'"GET / HTTP/1.1" 200 0 "-" "-"', log_new)
            is not None
        ), 'rename new'
        assert not os.path.isfile(log_path), 'rename old'

        with open(temp_dir + '/unit.pid', 'r') as f:
            pid = f.read().rstrip()

        call(['kill', '-s', 'USR1', pid])

        assert waitforfiles(log_path), 'reopen'

        assert self.get(url='/usr1')['status'] == 200

        unit_stop()

        assert (
            self.wait_for_record(r'"GET /usr1 HTTP/1.1" 200 0 "-" "-"', log)
            is not None
        ), 'reopen 2'
        assert self.search_in_log(r'/usr1', log_new) is None, 'rename new 2'

    def test_usr1_unit_log(self, temp_dir):
        self.load('log_body')

        log_new = 'new.log'
        log_path = temp_dir + '/unit.log'
        log_path_new = temp_dir + '/' + log_new

        os.rename(log_path, log_path_new)

        body = 'body_for_a_log_new'
        assert self.post(body=body)['status'] == 200

        assert self.wait_for_record(body, log_new) is not None, 'rename new'
        assert not os.path.isfile(log_path), 'rename old'

        with open(temp_dir + '/unit.pid', 'r') as f:
            pid = f.read().rstrip()

        call(['kill', '-s', 'USR1', pid])

        assert waitforfiles(log_path), 'reopen'

        body = 'body_for_a_log_unit'
        assert self.post(body=body)['status'] == 200

        unit_stop()

        assert self.wait_for_record(body) is not None, 'rename new'
        assert self.search_in_log(body, log_new) is None, 'rename new 2'

        # merge two log files into unit.log to check alerts

        with open(log_path, 'w') as unit_log, open(
            log_path_new, 'r'
        ) as unit_log_new:
            unit_log.write(unit_log_new.read())
