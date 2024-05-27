async def application_201(scope, receive, send):
    assert scope['type'] == 'http'

    await send(
        {
            'type': 'http.response.start',
            'status': 201,
            'headers': [(b'content-length', b'0')],
        }
    )


async def application_200(scope, receive, send):
    assert scope['type'] == 'http'

    await send(
        {
            'type': 'http.response.start',
            'status': 200,
            'headers': [(b'content-length', b'0')],
        }
    )


async def application_prefix(scope, receive, send):
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


def legacy_application_200(scope):
    assert scope['type'] == 'http'

    return legacy_app_http_200


async def legacy_app_http_200(receive, send):
    await send(
        {
            'type': 'http.response.start',
            'status': 200,
            'headers': [(b'content-length', b'0')],
        }
    )


def legacy_application_201(scope, receive=None, send=None):
    assert scope['type'] == 'http'

    return legacy_app_http_201


async def legacy_app_http_201(receive, send):
    await send(
        {
            'type': 'http.response.start',
            'status': 201,
            'headers': [(b'content-length', b'0')],
        }
    )
