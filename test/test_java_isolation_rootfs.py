import os
import subprocess

import pytest

from unit.applications.lang.java import ApplicationJava
from unit.option import option

prerequisites = {'modules': {'java': 'all'}, 'privileged_user': True}

client = ApplicationJava()


@pytest.fixture(autouse=True)
def setup_method_fixture(temp_dir):
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
            check=True,
        )

    except KeyboardInterrupt:
        raise

    except subprocess.CalledProcessError:
        pytest.fail("Can't run mount process.")

    yield

    try:
        subprocess.run(
            ["umount", "--lazy", f"{option.temp_dir}/jars"],
            stderr=subprocess.STDOUT,
            check=True,
        )

    except KeyboardInterrupt:
        raise

    except subprocess.CalledProcessError:
        pytest.fail("Can't run umount process.")


def test_java_isolation_rootfs_chroot_war(temp_dir):
    client.load('empty_war', isolation={'rootfs': temp_dir})

    assert 'success' in client.conf(
        '"/"',
        '/config/applications/empty_war/working_directory',
    )

    assert 'success' in client.conf(
        '"/jars"', 'applications/empty_war/unit_jars'
    )
    assert 'success' in client.conf(
        '"/java/empty.war"', 'applications/empty_war/webapp'
    )

    assert client.get()['status'] == 200, 'war'
