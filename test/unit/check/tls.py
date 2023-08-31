import re
import subprocess


def check_openssl(output_version):
    try:
        subprocess.check_output(['which', 'openssl'])
    except subprocess.CalledProcessError:
        return False

    return re.search('--openssl', output_version)
