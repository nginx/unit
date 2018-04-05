class application:
    def __init__(self, environ, start_response):
        self.environ = environ
        self.start = start_response

    def __iter__(self):
        self.start('200', [(('Content-Length', '0'))])
