def application(environ, start_response):

    content_length = int(environ.get('CONTENT_LENGTH', 0))
    body = bytes(environ['wsgi.input'].read(content_length))

    start_response('200', [
        ('Content-Type', environ.get('CONTENT_TYPE')),
        ('Content-Length', str(len(body))),
        ('Request-Method', environ.get('REQUEST_METHOD')),
        ('Request-Uri', environ.get('REQUEST_URI')),
        ('Http-Host', environ.get('HTTP_HOST')),
        ('Server-Protocol', environ.get('SERVER_PROTOCOL')),
        ('Custom-Header', environ.get('HTTP_CUSTOM_HEADER'))
    ])
    return [body]
