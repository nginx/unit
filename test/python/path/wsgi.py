import os
import sys


def application(environ, start_response):
    body = os.pathsep.join(sys.path).encode()

    start_response('200', [('Content-Length', str(len(body)))])
    return [body]
