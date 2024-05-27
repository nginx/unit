def application(scope):
    assert scope['type'] == 'http'

    return app_http


async def app_http(receive, send):
    await send(
        {
            'type': 'http.response.start',
            'status': 200,
            'headers': [
                (b'content-length', b'0'),
            ],
        }
    )
