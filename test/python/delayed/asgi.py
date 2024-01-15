import asyncio


async def application(scope, receive, send):
    assert scope['type'] == 'http'

    body = b''
    while True:
        m = await receive()
        body += m.get('body', b'')
        if not m.get('more_body', False):
            break

    headers = scope.get('headers', [])

    def get_header(n, v=None):
        for h in headers:
            if h[0] == n:
                return h[1]
        return v

    parts = int(get_header(b'x-parts', 1))
    delay = int(get_header(b'x-delay', 0))

    loop = asyncio.get_event_loop()

    async def sleep(n):
        future = loop.create_future()
        loop.call_later(n, future.set_result, None)
        await future

    await send(
        {
            'type': 'http.response.start',
            'status': 200,
            'headers': [
                (b'content-length', str(len(body)).encode()),
            ],
        }
    )

    if not body:
        await sleep(delay)
        return

    step = int(len(body) / parts)
    for i in range(0, len(body), step):
        await send(
            {
                'type': 'http.response.body',
                'body': body[i : i + step],
                'more_body': True,
            }
        )

        await sleep(delay)
