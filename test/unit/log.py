UNIT_LOG = 'unit.log'


class Log:
    temp_dir = None
    pos = {}

    def open(name=UNIT_LOG, encoding=None):
        f = open(Log.get_path(name), 'r', encoding=encoding, errors='ignore')
        f.seek(Log.pos.get(name, 0))

        return f

    def set_pos(pos, name=UNIT_LOG):
        Log.pos[name] = pos

    def swap(name):
        pos = Log.pos.get(UNIT_LOG, 0)
        Log.pos[UNIT_LOG] = Log.pos.get(name, 0)
        Log.pos[name] = pos

    def get_path(name=UNIT_LOG):
        return Log.temp_dir + '/' + name
