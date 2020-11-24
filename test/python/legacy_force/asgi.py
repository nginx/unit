def application(scope, receive=None, send=None):
    assert scope['type'] == 'http'

    if receive == None and send == None:
        return app_http

    else:
        return app_http(receive, send)

async def app_http(receive, send):
    await send({
        'type': 'http.response.start',
        'status': 200,
        'headers': [
            (b'content-length', b'0'),
        ]
    })
