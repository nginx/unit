import os
import re
import sys
import time

from unit.option import option

UNIT_LOG = 'unit.log'


def print_log_on_assert(func):
    def inner_function(*args, **kwargs):
        try:
            func(*args, **kwargs)
        except AssertionError as exception:
            Log.print_log(*args, **kwargs)
            raise exception

    return inner_function


class Log:
    pos = {}

    @staticmethod
    @print_log_on_assert
    def check_alerts(log=None):
        if log is None:
            log = Log.read()

        found = False
        alerts = re.findall(r'.+\[alert\].+', log)

        if alerts:
            found = True

            if option.detailed:
                print('\nAll alerts/sanitizer errors found in log:')
                _ = [print(alert) for alert in alerts]

        if option.skip_alerts:
            for skip in option.skip_alerts:
                alerts = [al for al in alerts if re.search(skip, al) is None]

        assert not alerts, 'alert(s)'

        if not option.skip_sanitizer:
            sanitizer_errors = re.findall('.+Sanitizer.+', log)

            assert not sanitizer_errors, 'sanitizer error(s)'

        if found and option.detailed:
            print('skipped.')

    @staticmethod
    def findall(pattern, name=UNIT_LOG, flags=re.M):
        return re.findall(pattern, Log.read(name), flags)

    @staticmethod
    def get_path(name=UNIT_LOG):
        return f'{option.temp_dir}/{name}'

    @staticmethod
    def open(name=UNIT_LOG, encoding='utf-8'):
        file = open(Log.get_path(name), 'r', encoding=encoding, errors='ignore')
        file.seek(Log.pos.get(name, 0))

        return file

    @staticmethod
    def print_log(log=None):
        Log.print_path()

        if option.print_log:
            os.set_blocking(sys.stdout.fileno(), True)
            sys.stdout.flush()

            if log is None:
                log = Log.read()

            sys.stdout.write(log)

    @staticmethod
    def print_path():
        print(f'Path to {UNIT_LOG}:\n{Log.get_path()}\n')

    @staticmethod
    def read(*args, **kwargs):
        with Log.open(*args, **kwargs) as file:
            return file.read()

    @staticmethod
    def set_pos(pos, name=UNIT_LOG):
        Log.pos[name] = pos

    @staticmethod
    def swap(name):
        pos = Log.pos.get(UNIT_LOG, 0)
        Log.pos[UNIT_LOG] = Log.pos.get(name, 0)
        Log.pos[name] = pos

    @staticmethod
    def wait_for_record(pattern, name=UNIT_LOG, wait=150, flags=re.M):
        with Log.open(name) as file:
            for _ in range(wait):
                found = re.search(pattern, file.read(), flags)

                if found is not None:
                    break

                time.sleep(0.1)

        return found
