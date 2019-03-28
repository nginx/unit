import re
import time
from unit.control import TestControl


class TestApplicationProto(TestControl):
    def sec_epoch(self):
        return time.mktime(time.gmtime())

    def date_to_sec_epoch(self, date, template='%a, %d %b %Y %H:%M:%S %Z'):
        return time.mktime(time.strptime(date, template))

    def search_in_log(self, pattern):
        with open(self.testdir + '/unit.log', 'r', errors='ignore') as f:
            return re.search(pattern, f.read())
