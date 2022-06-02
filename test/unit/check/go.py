from unit.applications.lang.go import TestApplicationGo


def check_go():
    process = TestApplicationGo.prepare_env('empty')

    if process != None and process.returncode == 0:
        return True
