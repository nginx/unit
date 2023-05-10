import os


def application(env, start_response):
    vars = env.get('HTTP_X_VARIABLES').split(',')

    body = ','.join([str(os.environ[var]) for var in vars if var in os.environ])
    body = body.encode()

    start_response('200', [('Content-Length', str(len(body)))])
    return body
