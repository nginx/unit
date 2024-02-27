import os
import platform


class Options:
    _options = {
        'architecture': platform.architecture()[0],
        'available': {'modules': {}, 'features': {}},
        'configure_flag': {},
        'is_privileged': os.geteuid() == 0,
        'skip_alerts': [],
        'skip_sanitizer': False,
        'system': platform.system(),
    }

    def __setattr__(self, name, value):
        Options._options[name] = value

    def __getattr__(self, name):
        if name in Options._options:
            return Options._options[name]

        raise AttributeError


option = Options()
