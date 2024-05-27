async def application(scope, receive, send):
    assert scope['type'] == 'http'

    body = b''
    while True:
        m = await receive()
        body += m.get('body', b'')
        if not m.get('more_body', False):
            break

    headers = scope.get('headers', [])

    def get_header(n):
        res = []
        for h in headers:
            if h[0] == n:
                res.append(h[1])
        return b', '.join(res)

    await send(
        {
            'type': 'http.response.start',
            'status': 200,
            'headers': [
                (b'content-type', get_header(b'content-type')),
                (b'content-length', str(len(body)).encode()),
                (b'request-method', scope['method'].encode()),
                (b'request-uri', scope['path'].encode()),
                (b'http-host', get_header(b'host')),
                (b'http-version', scope['http_version'].encode()),
                (b'asgi-version', scope['asgi']['version'].encode()),
                (b'asgi-spec-version', scope['asgi']['spec_version'].encode()),
                (b'scheme', scope['scheme'].encode()),
                (b'custom-header', get_header(b'custom-header')),
            ],
        }
    )

    await send({'type': 'http.response.body', 'body': body})
