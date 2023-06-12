import os
import subprocess

import pytest
from unit.applications.lang.java import TestApplicationJava
from unit.option import option

prerequisites = {'modules': {'java': 'all'}, 'privileged_user': True}


class TestJavaIsolationRootfs(TestApplicationJava):
    @pytest.fixture(autouse=True)
    def setup_method_fixture(self, temp_dir):
        os.makedirs(f'{temp_dir}/jars')
        os.makedirs(f'{temp_dir}/tmp')
        os.chmod(f'{temp_dir}/tmp', 0o777)

        try:
            subprocess.run(
                [
                    "mount",
                    "--bind",
                    f'{option.current_dir}/build',
                    f'{temp_dir}/jars',
                ],
                stderr=subprocess.STDOUT,
            )

        except KeyboardInterrupt:
            raise

        except subprocess.CalledProcessError:
            pytest.fail("Can't run mount process.")

    def teardown_method(self):
        try:
            subprocess.run(
                ["umount", "--lazy", f"{option.temp_dir}/jars"],
                stderr=subprocess.STDOUT,
            )

        except KeyboardInterrupt:
            raise

        except subprocess.CalledProcessError:
            pytest.fail("Can't run umount process.")

    def test_java_isolation_rootfs_chroot_war(self, temp_dir):
        isolation = {'rootfs': temp_dir}

        self.load('empty_war', isolation=isolation)

        assert 'success' in self.conf(
            '"/"',
            '/config/applications/empty_war/working_directory',
        )

        assert 'success' in self.conf(
            '"/jars"', 'applications/empty_war/unit_jars'
        )
        assert 'success' in self.conf(
            '"/java/empty.war"', 'applications/empty_war/webapp'
        )

        assert self.get()['status'] == 200, 'war'
