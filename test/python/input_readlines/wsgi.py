def application(environ, start_response):
    body = environ['wsgi.input'].readlines()

    start_response('200', [('X-Lines-Count', str(len(body)))])
    return body
