from unit.applications.lang.go import ApplicationGo


def check_go():
    return ApplicationGo.prepare_env('empty') is not None
