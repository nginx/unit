import pytest
from unit.applications.lang.go import TestApplicationGo

prerequisites = {
    'modules': {'go': 'all'},
    'features': {'isolation': True},
    'privileged_user': True,
}


class TestGoIsolationRootfs(TestApplicationGo):
    @pytest.fixture(autouse=True)
    def setup_method_fixture(self, skip_alert):
        skip_alert(r'\[unit\] close\(\d+\) failed: Bad file descriptor')

    def test_go_isolation_rootfs_chroot(self, temp_dir):
        isolation = {'rootfs': temp_dir}

        self.load('ns_inspect', isolation=isolation)

        obj = self.getjson(url='/?file=/go/app')['body']

        assert obj['FileExists'], 'app relative to rootfs'

        obj = self.getjson(url='/?file=/bin/sh')['body']
        assert not obj['FileExists'], 'file should not exists'
