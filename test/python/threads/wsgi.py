import threading
import time


def application(environ, start_response):
    delay = float(environ.get('HTTP_X_DELAY', 0))

    time.sleep(delay)

    start_response(
        '200',
        [
            ('Content-Length', '0'),
            ('Wsgi-Multithread', str(environ['wsgi.multithread'])),
            ('X-Thread', str(threading.currentThread().ident)),
        ],
    )

    return []
