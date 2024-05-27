def application(environ, start_response):

    content_length = int(environ.get('CONTENT_LENGTH', 0))
    body = bytes(environ['wsgi.input'].read(content_length))

    start_response(
        '200',
        [
            ('Content-Type', environ.get('CONTENT_TYPE')),
            ('Content-Length', str(len(body))),
            ('Request-Method', environ.get('REQUEST_METHOD')),
            ('Request-Uri', environ.get('REQUEST_URI')),
            ('Http-Host', environ.get('HTTP_HOST')),
            ('Server-Protocol', environ.get('SERVER_PROTOCOL')),
            ('Server-Software', environ.get('SERVER_SOFTWARE')),
            ('Custom-Header', environ.get('HTTP_CUSTOM_HEADER')),
            ('Wsgi-Version', str(environ['wsgi.version'])),
            ('Wsgi-Url-Scheme', environ['wsgi.url_scheme']),
            ('Wsgi-Multithread', str(environ['wsgi.multithread'])),
            ('Wsgi-Multiprocess', str(environ['wsgi.multiprocess'])),
            ('Wsgi-Run-Once', str(environ['wsgi.run_once'])),
        ],
    )
    return [body]
