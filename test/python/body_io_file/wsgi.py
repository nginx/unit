def application(env, start_response):
    start_response('200', [('Content-Length', '5')])
    f = open('file', 'rb')
    return f
