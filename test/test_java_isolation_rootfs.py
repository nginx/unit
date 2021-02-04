import os
import subprocess

import pytest
from unit.applications.lang.java import TestApplicationJava
from unit.option import option


class TestJavaIsolationRootfs(TestApplicationJava):
    prerequisites = {'modules': {'java': 'all'}}

    def setup_method(self, is_su):
        if not is_su:
            return

        os.makedirs(option.temp_dir + '/jars')
        os.makedirs(option.temp_dir + '/tmp')
        os.chmod(option.temp_dir + '/tmp', 0o777)

        try:
            process = subprocess.Popen(
                [
                    "mount",
                    "--bind",
                    option.current_dir + "/build",
                    option.temp_dir + "/jars",
                ],
                stderr=subprocess.STDOUT,
            )

            process.communicate()

        except KeyboardInterrupt:
            raise

        except:
            pytest.fail('Can\'t run mount process.')

    def teardown_method(self, is_su):
        if not is_su:
            return

        try:
            process = subprocess.Popen(
                ["umount", "--lazy", option.temp_dir + "/jars"],
                stderr=subprocess.STDOUT,
            )

            process.communicate()

        except KeyboardInterrupt:
            raise

        except:
            pytest.fail('Can\'t run mount process.')

    def test_java_isolation_rootfs_chroot_war(self, is_su, temp_dir):
        if not is_su:
            pytest.skip('require root')

        isolation = {
            'rootfs': temp_dir,
        }

        self.load('empty_war', isolation=isolation)

        assert 'success' in self.conf(
            '"/"', '/config/applications/empty_war/working_directory',
        )

        assert 'success' in self.conf(
            '"/jars"', 'applications/empty_war/unit_jars'
        )
        assert 'success' in self.conf(
            '"/java/empty.war"', 'applications/empty_war/webapp'
        )

        assert self.get()['status'] == 200, 'war'
