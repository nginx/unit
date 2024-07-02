def wsgi_a(env, start_response):
    start_response("200", [("Content-Length", "1")])
    return [b"1"]


def wsgi_b(env, start_response):
    start_response("200", [("Content-Length", "1")])
    return [b"2"]


def wsgi_a_factory():
    return wsgi_a


def wsgi_b_factory():
    return wsgi_b


wsgi_invalid_callable = None


def wsgi_factory_returning_invalid_callable():
    return wsgi_invalid_callable
