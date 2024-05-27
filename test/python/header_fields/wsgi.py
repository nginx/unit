def application(environ, start_response):

    h = (k for k, v in environ.items() if k.startswith('HTTP_'))

    start_response(
        '200', [('Content-Length', '0'), ('All-Headers', ','.join(h))]
    )
    return []
