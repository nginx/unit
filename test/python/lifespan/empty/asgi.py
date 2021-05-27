import os


async def handler(prefix, scope, receive, send):
    if scope['type'] == 'lifespan':
        with open(prefix + 'version', 'w+') as f:
            f.write(
                scope['asgi']['version'] + ' ' + scope['asgi']['spec_version']
            )
        while True:
            message = await receive()
            if message['type'] == 'lifespan.startup':
                os.remove(prefix + 'startup')
                await send({'type': 'lifespan.startup.complete'})
            elif message['type'] == 'lifespan.shutdown':
                os.remove(prefix + 'shutdown')
                await send({'type': 'lifespan.shutdown.complete'})
                return

    if scope['type'] == 'http':
        await send(
            {
                'type': 'http.response.start',
                'status': 204,
                'headers': [(b'content-length', b'0'),],
            }
        )


async def application(scope, receive, send):
    return await handler('', scope, receive, send)


async def application2(scope, receive, send):
    return await handler('app2_', scope, receive, send)
