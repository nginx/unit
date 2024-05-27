def application(environ, start_response):
    temp_dir = environ.get('HTTP_TEMP_DIR')

    with open(f'{temp_dir}/tempfile', 'w', encoding='utf-8') as f:
        f.write('\u26a0\ufe0f')

    start_response('200', [('Content-Length', '0')])
    return []
