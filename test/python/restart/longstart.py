import os
import time

time.sleep(2)


def application(environ, start_response):
    body = str(os.getpid()).encode()

    start_response('200', [('Content-Length', str(len(body)))])
    return [body]
