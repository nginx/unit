def application(environ, start_response):

    start_response(
        '200',
        [('Content-Length', '0'), ('Server-Port', environ.get('SERVER_PORT'))],
    )
    return []
