class application:
    def __init__(self, environ, start_response):
        self.environ = environ
        self.start = start_response

    def __iter__(self):
        self.start('200', [(('Content-Length', '0'))])
        yield b''

    def close(self):
        self.environ['wsgi.errors'].write('Close called.\n')
        self.environ['wsgi.errors'].flush()
