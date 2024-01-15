class application:
    def __init__(self, environ, start_response):
        self.environ = environ
        self.start = start_response

        self.next = self.__next__

    def __iter__(self):
        self.__i = 0
        self._skip_level = int(self.environ.get('HTTP_X_SKIP', 0))
        self._not_skip_close = int(self.environ.get('HTTP_X_NOT_SKIP_CLOSE', 0))
        self._is_chunked = self.environ.get('HTTP_X_CHUNKED')

        headers = [(('Content-Length', '10'))]
        if self._is_chunked is not None:
            headers = []

        if self._skip_level < 1:
            raise Exception('first exception')

        write = self.start('200', headers)

        if self._skip_level < 2:
            raise Exception('second exception')

        write(b'XXXXX')

        if self._skip_level < 3:
            raise Exception('third exception')

        return self

    def __next__(self):
        if self._skip_level < 4:
            raise Exception('next exception')

        self.__i += 1
        if self.__i > 2:
            raise StopIteration

        return b'X'

    def close(self):
        if self._not_skip_close == 1:
            raise Exception('close exception')
