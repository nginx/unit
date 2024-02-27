import json

from unit.http import HTTP1
from unit.option import option

http = HTTP1()


def check_chroot():
    return (
        'success'
        in http.put(
            url='/config',
            sock_type='unix',
            addr=f'{option.temp_dir}/control.unit.sock',
            body=json.dumps(
                {
                    "listeners": {"*:8080": {"pass": "routes"}},
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
        )['body']
    )
