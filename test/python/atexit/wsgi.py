import atexit


def application(environ, start_response):
    def at_exit():
        environ['wsgi.errors'].write('At exit called.\n')
        environ['wsgi.errors'].flush()

    atexit.register(at_exit)

    start_response('200', [('Content-Length', '0')])
    return []
