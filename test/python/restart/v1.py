def application(environ, start_response):
    body = "v1".encode()

    start_response('200', [('Content-Length', str(len(body)))])
    return [body]
