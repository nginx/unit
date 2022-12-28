async def application(scope, receive, send):
    assert scope['type'] == 'http'

    await send(
        {
            'type': 'http.response.start',
            'status': 200,
            'headers': [
                (b'content-length', b'0'),
                (b'prefix', scope.get('root_path', 'NULL').encode()),
            ],
        }
    )

    await send({'type': 'http.response.body', 'body': b''})
