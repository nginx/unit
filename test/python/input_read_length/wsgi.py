def application(environ, start_response):

    input_length = int(environ.get('HTTP_INPUT_LENGTH'))
    body = bytes(environ['wsgi.input'].read(input_length))

    start_response('200', [('Content-Length', str(len(body)))])
    return [body]
