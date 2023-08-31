import glob
import os
import socket
import subprocess
import time

import pytest


def public_dir(path):
    os.chmod(path, 0o777)

    for root, dirs, files in os.walk(path):
        for d in dirs:
            try:
                os.chmod(os.path.join(root, d), 0o777)
            except FileNotFoundError:
                pass
        for f in files:
            try:
                os.chmod(os.path.join(root, f), 0o777)
            except FileNotFoundError:
                pass


def waitforfiles(*files, timeout=50):
    for _ in range(timeout):
        wait = False

        for f in files:
            if not os.path.exists(f):
                wait = True
                break

        if not wait:
            return True

        time.sleep(0.1)

    return False


def waitforglob(pattern, count=1, timeout=50):
    for _ in range(timeout):
        n = 0

        for _ in glob.glob(pattern):
            n += 1

        if n == count:
            return True

        time.sleep(0.1)

    return False


def waitforsocket(port):
    for _ in range(50):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.settimeout(5)
                sock.connect(('127.0.0.1', port))
                return

            except ConnectionRefusedError:
                time.sleep(0.1)

            except KeyboardInterrupt:
                raise

    pytest.fail(f"Can't connect to the 127.0.0.1:{port}")


def check_findmnt():
    try:
        return subprocess.check_output(
            ['findmnt', '--raw'], stderr=subprocess.STDOUT
        ).decode()
    except FileNotFoundError:
        return False


def findmnt():
    out = check_findmnt()

    if not out:
        pytest.skip('requires findmnt')

    return out


def waitformount(template, timeout=50):
    for _ in range(timeout):
        if findmnt().find(template) != -1:
            return True

        time.sleep(0.1)

    return False


def waitforunmount(template, timeout=50):
    for _ in range(timeout):
        if findmnt().find(template) == -1:
            return True

        time.sleep(0.1)

    return False


def getns(nstype):
    # read namespace id from symlink file:
    # it points to: '<nstype>:[<ns id>]'
    # # eg.: 'pid:[4026531836]'
    nspath = f'/proc/self/ns/{nstype}'
    data = None

    if os.path.exists(nspath):
        data = int(os.readlink(nspath)[len(nstype) + 2 : -1])

    return data
