import json
import os


def application(environ, start_response):
    uid = os.geteuid()
    gid = os.getegid()

    out = json.dumps(
        {
            'UID': uid,
            'GID': gid,
        }
    ).encode('utf-8')

    start_response(
        '200 OK',
        [
            ('Content-Length', str(len(out))),
            ('Content-Type', 'application/json'),
        ],
    )

    return [out]
