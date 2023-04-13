import os
import subprocess

import pytest
from unit.applications.lang.java import TestApplicationJava
from unit.option import option


class TestJavaIsolationRootfs(TestApplicationJava):
    prerequisites = {'modules': {'java': 'all'}}

    def setup_method(self, is_su):
        if not is_su:
            pytest.skip('require root')

        os.makedirs(f'{option.temp_dir}/jars')
        os.makedirs(f'{option.temp_dir}/tmp')
        os.chmod(f'{option.temp_dir}/tmp', 0o777)

        try:
            subprocess.run(
                [
                    "mount",
                    "--bind",
                    f'{option.current_dir}/build',
                    f'{option.temp_dir}/jars',
                ],
                stderr=subprocess.STDOUT,
            )

        except KeyboardInterrupt:
            raise

        except subprocess.CalledProcessError:
            pytest.fail("Can't run mount process.")

    def teardown_method(self, is_su):
        if not is_su:
            return

        try:
            subprocess.run(
                ["umount", "--lazy", f"{option.temp_dir}/jars"],
                stderr=subprocess.STDOUT,
            )

        except KeyboardInterrupt:
            raise

        except subprocess.CalledProcessError:
            pytest.fail("Can't run umount process.")

    def test_java_isolation_rootfs_chroot_war(self, is_su, temp_dir):
        if not is_su:
            pytest.skip('require root')

        isolation = {
            'rootfs': temp_dir,
        }

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
