def application(environ, start_response):
    content_length = int(environ.get('CONTENT_LENGTH', 0))
    body = bytes(environ['wsgi.input'].read(content_length))

    environ['wsgi.errors'].write(body.decode())
    environ['wsgi.errors'].flush()

    start_response('200', [('Content-Length', '0')])
    return []
