from unit.applications.lang.go import TestApplicationGo


def check_go():
    if TestApplicationGo.prepare_env('empty') is not None:
        return True
