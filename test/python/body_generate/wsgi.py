def application(env, start_response):
    length = env.get('HTTP_X_LENGTH', '10')
    body = b'X' * int(length)

    start_response('200', [('Content-Length', length)])
    return [body]
