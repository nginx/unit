import io


def application(env, start_response):
    start_response('200', [('Content-Length', '10')])
    f = io.BytesIO(b'0123456789')
    return f
