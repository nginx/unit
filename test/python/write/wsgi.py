def application(env, start_response):
    write = start_response('200', [('Content-Length', '10')])
    write(b'012')
    write(b'345')
    return b'6789'
