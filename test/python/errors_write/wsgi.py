def application(environ, start_response):
    environ['wsgi.errors'].write('Error in application.')

    start_response('200', [('Content-Length', '0')])
    return []
