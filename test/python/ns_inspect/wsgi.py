import json
import os
import sys

try:
    # Python 3
    from urllib.parse import parse_qs
except ImportError:
    # Python 2
    from urlparse import parse_qs


def application(environ, start_response):
    print("pwd:", os.getcwd())
    print("sys.path:\n", sys.path, file=sys.stdout)

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
