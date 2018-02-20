def application(environ, start_response):

    content_length = int(environ.get('CONTENT_LENGTH', 0))
    body = bytes(environ['wsgi.input'].read(content_length))

    start_response('200', [
        ('Content-Type', environ.get('CONTENT_TYPE')),
        ('Content-Length', str(len(body)))
    ])
    return [body]
