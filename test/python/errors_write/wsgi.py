def application(environ, start_response):
    environ['wsgi.errors'].write('Error in application.')
    environ['wsgi.errors'].flush()

    start_response('200', [('Content-Length', '0')])
    return []
