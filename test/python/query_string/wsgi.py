def application(environ, start_response):

    start_response(
        '200',
        [
            ('Content-Length', '0'),
            ('Query-String', environ.get('QUERY_STRING')),
        ],
    )
    return []
