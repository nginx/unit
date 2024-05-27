def application(env, start_response):
    start_response(
        '200',
        [
            ('Content-Length', '0'),
            ('X-Server-Name', env.get('SERVER_NAME')),
            ('X-Http-Host', str(env.get('HTTP_HOST'))),
        ],
    )
    return []
