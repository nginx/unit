async def application(scope, receive, send):
    if scope['type'] == 'websocket':
        while True:
            m = await receive()
            if m['type'] == 'websocket.connect':
                await send({'type': 'websocket.accept'})

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
