def application(env, start_response):
    ip = env['REMOTE_ADDR'].encode()
    start_response('200', [('Content-Length', str(len(ip)))])
    return ip
