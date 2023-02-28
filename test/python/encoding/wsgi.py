import sys


def application(environ, start_response):
    start_response(
        '200',
        [
            ('Content-Length', '0'),
            ('X-Encoding', sys.getfilesystemencoding()),
        ],
    )
    return []
