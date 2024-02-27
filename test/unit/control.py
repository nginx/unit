import json

from unit.http import HTTP1
from unit.option import option


def args_handler(conf_func):
    def args_wrapper(self, *args):
        argcount = conf_func.__code__.co_argcount
        url_default = '/config'
        conf = None

        if argcount == 2:
            url = args[0] if len(args) == 1 else url_default

        elif argcount == 3:
            conf = args[0]

            if isinstance(conf, (dict, list)):
                conf = json.dumps(conf)

            url = args[1] if len(args) == 2 else url_default

        url = url if url.startswith('/') else f'{url_default}/{url}'
        arguments = (self, url) if conf is None else (self, conf, url)

        return json.loads(conf_func(*arguments))

    return args_wrapper


class Control(HTTP1):
    @args_handler
    def conf(self, conf, url):
        return self.put(**self._get_args(url, conf))['body']

    @args_handler
    def conf_get(self, url):
        return self.get(**self._get_args(url))['body']

    @args_handler
    def conf_delete(self, url):
        return self.delete(**self._get_args(url))['body']

    @args_handler
    def conf_post(self, conf, url):
        return self.post(**self._get_args(url, conf))['body']

    def _get_args(self, url, conf=None):
        args = {
            'url': url,
            'sock_type': 'unix',
            'addr': f'{option.temp_dir}/control.unit.sock',
        }

        if conf is not None:
            args['body'] = conf

        return args
