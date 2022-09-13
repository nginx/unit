import json

from unit.http import TestHTTP
from unit.option import option

http = TestHTTP()


def check_unix_abstract():
    available = option.available

    resp = http.put(
        url='/config',
        sock_type='unix',
        addr=option.temp_dir + '/control.unit.sock',
        body=json.dumps(
            {
                "listeners": {"unix:@sock": {"pass": "routes"}},
                "routes": [],
            }
        ),
    )

    if 'success' in resp['body']:
        available['features']['unix_abstract'] = True
