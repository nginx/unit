import json
from unit.http import TestHTTP


class TestControl(TestHTTP):

    # TODO socket reuse
    # TODO http client

    def conf(self, conf, path='/config'):
        if isinstance(conf, dict) or isinstance(conf, list):
            conf = json.dumps(conf)

        if path[:1] != '/':
            path = '/config/' + path

        return json.loads(
            self.put(
                url=path,
                body=conf,
                sock_type='unix',
                addr=self.testdir + '/control.unit.sock',
            )['body']
        )

    def conf_get(self, path='/config'):
        if path[:1] != '/':
            path = '/config/' + path

        return json.loads(
            self.get(
                url=path,
                sock_type='unix',
                addr=self.testdir + '/control.unit.sock',
            )['body']
        )

    def conf_delete(self, path='/config'):
        if path[:1] != '/':
            path = '/config/' + path

        return json.loads(
            self.delete(
                url=path,
                sock_type='unix',
                addr=self.testdir + '/control.unit.sock',
            )['body']
        )
