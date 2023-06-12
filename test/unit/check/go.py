from unit.applications.lang.go import TestApplicationGo


def check_go():
    return TestApplicationGo.prepare_env('empty') is not None
