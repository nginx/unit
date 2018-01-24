#!/usr/bin/env python3

import unittest
import sys
import os

loader = unittest.TestLoader()
suite  = unittest.TestSuite()

this_dir = os.path.dirname(__file__)
tests = loader.discover(start_dir=this_dir)
suite.addTests(tests)

runner = unittest.TextTestRunner(verbosity=3)
result = runner.run(suite)

ret = not (len(result.failures) == len(result.errors) == 0)

sys.exit(ret)
