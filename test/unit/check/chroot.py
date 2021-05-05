import json

from unit.http import TestHTTP
from unit.option import option

http = TestHTTP()


def check_chroot():
    available = option.available

    resp = http.put(
        url='/config',
        sock_type='unix',
        addr=option.temp_dir + '/control.unit.sock',
        body=json.dumps(
            {
                "listeners": {"*:7080": {"pass": "routes"}},
                "routes": [
                    {
                        "action": {
                            "share": option.temp_dir,
                            "chroot": option.temp_dir,
                        }
                    }
                ],
            }
        ),
    )

    if 'success' in resp['body']:
        available['features']['chroot'] = True
