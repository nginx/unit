class Options:
    _options = {
        'skip_alerts': [],
        'skip_sanitizer': False,
    }

    def __setattr__(self, name, value):
        Options._options[name] = value

    def __getattr__(self, name):
        if name in Options._options:
            return Options._options[name]

        raise AttributeError


option = Options()
