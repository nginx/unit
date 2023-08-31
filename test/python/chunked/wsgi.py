def application(environ, start_response):

    content_length = int(environ.get('CONTENT_LENGTH', 0))
    body = bytes(environ['wsgi.input'].read(content_length))

    header_transfer = environ.get('HTTP_X_TRANSFER')
    header_length = environ.get('HTTP_X_LENGTH')

    headers = []

    if header_length:
        headers.append(('Content-Length', '0'))

    if header_transfer:
        headers.append(('Transfer-Encoding', header_transfer))

    start_response('200', headers)
    return [body]
