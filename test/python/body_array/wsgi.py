def application(env, start_response):
    start_response('200', [('Content-Length', '10')])
    return [b'0123', b'4567', b'89']
