def application(environ, start_response):
    body = bytes(environ['wsgi.input'].__iter__())

    start_response('200', [('Content-Length', str(len(body)))])
    return [body]
