import os
import time
import unittest
import unit

class TestUnitPythonAtExit(unit.TestUnitApplicationPython):

    def setUpClass():
        unit.TestUnit().check_modules('python')

    def test_python_atexit(self):
        self.load('atexit')

        self.get(headers={
            'Host': 'localhost',
            'Test-Dir': self.testdir,
            'Connection': 'close'
        })

        self.conf({
            "listeners": {},
            "applications": {}
        })

        time.sleep(0.2)   # wait for 'atexit' file

        self.assertEqual(os.path.exists(self.testdir + '/atexit'), True,
            'python atexit')

if __name__ == '__main__':
    unittest.main()
