def application(environ, start_response):
    body = []
    content_length = 0

    for l in environ['wsgi.input'].__iter__():
        body.append(l)
        content_length += len(l)

    start_response(
        '200',
        [
            ('Content-Length', str(content_length)),
            ('X-Lines-Count', str(len(body))),
        ],
    )
    return body
