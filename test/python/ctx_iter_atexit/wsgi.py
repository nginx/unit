import atexit


class application:
    def __init__(self, environ, start_response):
        self.environ = environ
        self.start = start_response

    def __iter__(self):
        atexit.register(self._atexit)

        content_length = int(self.environ.get('CONTENT_LENGTH', 0))
        body = bytes(self.environ['wsgi.input'].read(content_length))

        self.start(
            '200',
            [
                ('Content-Length', str(len(body))),
            ],
        )
        yield body

    def _atexit(self):
        self.start('200', [('Content-Length', '0')])
