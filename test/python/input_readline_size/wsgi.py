def application(environ, start_response):
    body = []

    while True:
        l = environ['wsgi.input'].readline(9)
        if not l:
            break

        body.append(l)

        if len(l) > 9:
            body.append(f'len(l) > 9: {l}'.encode())
            break

    start_response('200', [('X-Lines-Count', str(len(body)))])
    return body
