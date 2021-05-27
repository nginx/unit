async def application(scope, receive, send):
    assert scope['type'] == 'http'

    body = b''
    while True:
        m = await receive()
        body += m.get('body', b'')
        if not m.get('more_body', False):
            break

    await send(
        {
            'type': 'http.response.start',
            'status': 200,
            'headers': [(b'content-length', str(len(body)).encode())],
        }
    )

    await send({'type': 'http.response.body', 'body': body})
