import time


def application(environ, start_response):
    parts = int(environ.get('HTTP_X_PARTS', 1))
    delay = int(environ.get('HTTP_X_DELAY', 0))

    content_length = int(environ.get('CONTENT_LENGTH', 0))
    body = bytes(environ['wsgi.input'].read(content_length))

    write = start_response('200', [('Content-Length', str(len(body)))])

    if not body:
        time.sleep(delay)
        return []

    step = int(len(body) / parts)
    for i in range(0, len(body), step):
        try:
            write(body[i : i + step])
        except:
            break

        time.sleep(delay)

    return []
