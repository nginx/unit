def wsgi_target_a(env, start_response):
    start_response('200', [('Content-Length', '1')])
    return [b'1']


def wsgi_target_b(env, start_response):
    start_response('200', [('Content-Length', '1')])
    return [b'2']


def wsgi_target_prefix(env, start_response):
    data = f"{env.get('SCRIPT_NAME', 'No Script Name')} {env['PATH_INFO']}"
    start_response('200', [('Content-Length', f'{data}')])
    return [data.encode('utf-8')]
