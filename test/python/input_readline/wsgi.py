def application(environ, start_response):
    body = []
    content_length = 0

    while True:
        l = environ['wsgi.input'].readline()
        if not l:
            break

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
