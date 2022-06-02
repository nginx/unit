import os
import signal

from unit.applications.lang.python import TestApplicationPython
from unit.log import Log
from unit.utils import waitforfiles


class TestUSR1(TestApplicationPython):
    prerequisites = {'modules': {'python': 'any'}}

    def test_usr1_access_log(self, temp_dir, unit_pid):
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

        os.kill(unit_pid, signal.SIGUSR1)

        assert waitforfiles(log_path), 'reopen'

        assert self.get(url='/usr1')['status'] == 200

        assert (
            self.wait_for_record(r'"GET /usr1 HTTP/1.1" 200 0 "-" "-"', log)
            is not None
        ), 'reopen 2'
        assert self.search_in_log(r'/usr1', log_new) is None, 'rename new 2'

    def test_usr1_unit_log(self, temp_dir, unit_pid):
        self.load('log_body')

        log_new = 'new.log'
        log_path = temp_dir + '/unit.log'
        log_path_new = temp_dir + '/' + log_new

        os.rename(log_path, log_path_new)

        Log.swap(log_new)

        try:
            body = 'body_for_a_log_new\n'
            assert self.post(body=body)['status'] == 200

            assert self.wait_for_record(body, log_new) is not None, 'rename new'
            assert not os.path.isfile(log_path), 'rename old'

            os.kill(unit_pid, signal.SIGUSR1)

            assert waitforfiles(log_path), 'reopen'

            body = 'body_for_a_log_unit\n'
            assert self.post(body=body)['status'] == 200

            assert self.wait_for_record(body) is not None, 'rename new'
            assert self.search_in_log(body, log_new) is None, 'rename new 2'

        finally:
            # merge two log files into unit.log to check alerts

            with open(log_path, 'r', errors='ignore') as unit_log:
                log = unit_log.read()

            with open(log_path, 'w') as unit_log, open(
                log_path_new, 'r', errors='ignore'
            ) as unit_log_new:
                unit_log.write(unit_log_new.read())
                unit_log.write(log)

            Log.swap(log_new)
