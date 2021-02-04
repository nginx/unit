import os
import socket
import subprocess
import time

import pytest


def public_dir(path):
    os.chmod(path, 0o777)

    for root, dirs, files in os.walk(path):
        for d in dirs:
            os.chmod(os.path.join(root, d), 0o777)
        for f in files:
            os.chmod(os.path.join(root, f), 0o777)


def waitforfiles(*files):
    for i in range(50):
        wait = False

        for f in files:
            if not os.path.exists(f):
                wait = True
                break

        if not wait:
            return True

        time.sleep(0.1)

    return False


def waitforsocket(port):
    for i in range(50):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.settimeout(5)
                sock.connect(('127.0.0.1', port))
                return

            except ConnectionRefusedError:
                time.sleep(0.1)

            except KeyboardInterrupt:
                raise

    pytest.fail('Can\'t connect to the 127.0.0.1:' + port)


def findmnt():
    try:
        out = subprocess.check_output(
            ['findmnt', '--raw'], stderr=subprocess.STDOUT
        ).decode()
    except FileNotFoundError:
        pytest.skip('requires findmnt')

    return out


def waitformount(template, wait=50):
    for i in range(wait):
        if findmnt().find(template) != -1:
            return True

        time.sleep(0.1)

    return False


def waitforunmount(template, wait=50):
    for i in range(wait):
        if findmnt().find(template) == -1:
            return True

        time.sleep(0.1)

    return False


def getns(nstype):
    # read namespace id from symlink file:
    # it points to: '<nstype>:[<ns id>]'
    # # eg.: 'pid:[4026531836]'
    nspath = '/proc/self/ns/' + nstype
    data = None

    if os.path.exists(nspath):
        data = int(os.readlink(nspath)[len(nstype) + 2 : -1])

    return data
