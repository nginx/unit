def application(environ, start_response):

    start_response(
        '200',
        [
            ('Content-Length', '0'),
            ('Custom-Header', environ.get('HTTP_CUSTOM_HEADER')),
        ],
    )
    return []
