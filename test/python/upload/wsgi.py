import cgi
from tempfile import TemporaryFile


def read(environ):
    length = int(environ.get('CONTENT_LENGTH', 0))

    body = TemporaryFile(mode='w+b')
    body.write(bytes(environ['wsgi.input'].read(length)))
    body.seek(0)

    environ['wsgi.input'] = body
    return body


def application(environ, start_response):
    file = read(environ)

    form = cgi.FieldStorage(fp=file, environ=environ, keep_blank_values=True)

    filename = form['file'].filename
    data = filename.encode() + form['file'].file.read()

    start_response(
        '200 OK',
        [('Content-Type', 'text/plain'), ('Content-Length', str(len(data)))],
    )

    return data
