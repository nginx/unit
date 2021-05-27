def wsgi_target_a(env, start_response):
    start_response('200', [('Content-Length', '1')])
    return [b'1']


def wsgi_target_b(env, start_response):
    start_response('200', [('Content-Length', '1')])
    return [b'2']
