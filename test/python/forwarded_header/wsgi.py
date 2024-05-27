def application(env, start_response):
    start_response(
        '200',
        [
            ('Content-Length', '0'),
            ('Remote-Addr', env.get('REMOTE_ADDR')),
            ('Url-Scheme', env.get('wsgi.url_scheme')),
        ],
    )
    return []
