import time

def application(env, start_response):
    delay = int(env.get('HTTP_X_DELAY', 0))

    start_response('200', [('Content-Length', '0'), ('X-Upstream', '1')])
    time.sleep(delay)
    return []
