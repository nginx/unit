import threading
import time


async def application(scope, receive, send):
    assert scope['type'] == 'http'

    headers = scope.get('headers', [])

    def get_header(n, v=None):
        for h in headers:
            if h[0] == n:
                return h[1]
        return v

    delay = float(get_header(b'x-delay', 0))

    time.sleep(delay)

    await send(
        {
            'type': 'http.response.start',
            'status': 200,
            'headers': [
                (b'content-length', b'0'),
                (b'x-thread', str(threading.currentThread().ident).encode()),
            ],
        }
    )
