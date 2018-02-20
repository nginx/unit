import atexit

def application(environ, start_response):
    test_dir = environ.get('HTTP_TEST_DIR')

    def create_file():
        open(test_dir + '/atexit', 'w')

    atexit.register(create_file)

    start_response('200', [('Content-Length', '0')])
    return []
