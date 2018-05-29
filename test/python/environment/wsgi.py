import os

def application(env, start_response):
    body = ''
    vars = env.get('HTTP_X_VARIABLES').split(',')

    for var in vars:
        if var in os.environ:
            body += str(os.environ[var]) + ','

    body = body.encode()
    start_response('200', [('Content-Length', str(len(body)))])
    return body
