async def application(scope, receive, send):
    assert scope['type'] == 'http'

    await send(
        {
            'type': 'http.response.start',
            'status': 200,
            'headers': [(b'content-length', b'0')],
        }
    )
