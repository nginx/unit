def application(env, start_response):
    start_response('204', [('Content-Length', '0')])
    return []


def app(env, start_response):
    start_response('200', [('Content-Length', '0')])
    return []
