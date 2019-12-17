import sys
import time
import threading


class Foo(threading.Thread):
    num = 10

    def __init__(self, x):
        self.__x = x
        threading.Thread.__init__(self)

    def log_index(self, index):
        sys.stderr.write(
            "(" + str(index) + ") Thread: " + str(self.__x) + "\n"
        )
        sys.stderr.flush()

    def run(self):
        i = 0
        for _ in range(3):
            self.log_index(i)
            i += 1
            time.sleep(1)
            self.log_index(i)
            i += 1


def application(environ, start_response):
    Foo(Foo.num).start()
    Foo.num += 10
    start_response('200 OK', [('Content-Length', '0')])
    return []
