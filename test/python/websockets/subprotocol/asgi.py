async def application(scope, receive, send):
    assert scope['type'] == 'websocket'

    while True:
        m = await receive()
        if m['type'] == 'websocket.connect':
            subprotocols = scope['subprotocols']

            await send(
                {
                    'type': 'websocket.accept',
                    'headers': [
                        (b'x-subprotocols', str(subprotocols).encode()),
                    ],
                    'subprotocol': subprotocols[0],
                }
            )

        if m['type'] == 'websocket.receive':
            await send(
                {
                    'type': 'websocket.send',
                    'bytes': m.get('bytes', None),
                    'text': m.get('text', None),
                }
            )

        if m['type'] == 'websocket.disconnect':
            break
