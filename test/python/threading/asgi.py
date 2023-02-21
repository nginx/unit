import sys
import threading
import time


class Foo(threading.Thread):
    num = 10

    def __init__(self, x):
        self.__x = x
        threading.Thread.__init__(self)

    def log_index(self, index):
        sys.stderr.write(f'({index}) Thread: {self.__x}\n')
        sys.stderr.flush()

    def run(self):
        i = 0
        for _ in range(3):
            self.log_index(i)
            i += 1
            time.sleep(1)
            self.log_index(i)
            i += 1


async def application(scope, receive, send):
    assert scope['type'] == 'http'

    Foo(Foo.num).start()
    Foo.num += 10

    await send(
        {
            'type': 'http.response.start',
            'status': 200,
            'headers': [(b'content-length', b'0')],
        }
    )
