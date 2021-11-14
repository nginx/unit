def application(environ, start_response):
    start_response(
        '200',
        [
            ('Content-Length', '0'),
            ('Script-Name', environ.get('SCRIPT_NAME', 'No Script Name')),
            ('Path-Info', environ['PATH_INFO'])
        ]
    )
    return []