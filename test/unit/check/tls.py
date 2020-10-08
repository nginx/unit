import re
import subprocess


def check_openssl(unitd):
    subprocess.check_output(['which', 'openssl'])

    output = subprocess.check_output(
        [unitd, '--version'], stderr=subprocess.STDOUT
    )

    if re.search('--openssl', output.decode()):
        return True
