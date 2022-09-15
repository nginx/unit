from unit.control import TestControl


class Status:
    _status = None
    control = TestControl()

    def _check_zeros():
        assert Status.control.conf_get('/status') == {
            'connections': {
                'accepted': 0,
                'active': 0,
                'idle': 0,
                'closed': 0,
            },
            'requests': {'total': 0},
            'applications': {},
        }

    def init(status=None):
        Status._status = (
            status if status is not None else Status.control.conf_get('/status')
        )

    def diff():
        def find_diffs(d1, d2):
            if isinstance(d1, dict) and isinstance(d2, dict):
                return {
                    k: find_diffs(d1.get(k, 0), d2.get(k, 0))
                    for k in d1
                    if k in d2
                }
            else:
                return d1 - d2

        return find_diffs(Status.control.conf_get('/status'), Status._status)

    def get(path='/'):
        path = path.split('/')[1:]
        diff = Status.diff()

        for p in path:
            diff = diff[p]

        return diff
