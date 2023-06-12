from unit.applications.lang.python import TestApplicationPython

prerequisites = {'modules': {'python': 'any'}, 'privileged_user': True}


class TestPythonIsolation(TestApplicationPython):
    def test_python_isolation_chroot(self, temp_dir):
        isolation = {'rootfs': temp_dir}

        self.load('ns_inspect', isolation=isolation)

        assert not (
            self.getjson(url=f'/?path={temp_dir}')['body']['FileExists']
        ), 'temp_dir does not exists in rootfs'

        assert self.getjson(url='/?path=/proc/self')['body'][
            'FileExists'
        ], 'no /proc/self'

        assert not (
            self.getjson(url='/?path=/dev/pts')['body']['FileExists']
        ), 'no /dev/pts'

        assert not (
            self.getjson(url='/?path=/sys/kernel')['body']['FileExists']
        ), 'no /sys/kernel'

        ret = self.getjson(url='/?path=/app/python/ns_inspect')

        assert ret['body']['FileExists'], 'application exists in rootfs'
