import json
import os

try:
    # Python 3
    from urllib.parse import parse_qs
except ImportError:
    # Python 2
    from urlparse import parse_qs


def application(environ, start_response):
    ret = {
        'FileExists': False,
    }

    d = parse_qs(environ['QUERY_STRING'])

    ret['FileExists'] = os.path.exists(d.get('path')[0])

    out = json.dumps(ret)

    start_response(
        '200',
        [
            ('Content-Type', 'application/json'),
            ('Content-Length', str(len(out))),
        ],
    )

    return out.encode('utf-8')
