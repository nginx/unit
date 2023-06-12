import json

from unit.http import TestHTTP
from unit.option import option

http = TestHTTP()


def check_unix_abstract():
    return (
        'success'
        in http.put(
            url='/config',
            sock_type='unix',
            addr=f'{option.temp_dir}/control.unit.sock',
            body=json.dumps(
                {
                    "listeners": {
                        f'unix:@{option.temp_dir}/sock': {"pass": "routes"}
                    },
                    "routes": [],
                }
            ),
        )['body']
    )
