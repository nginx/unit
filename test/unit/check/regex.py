import re
import subprocess


def check_regex(unitd):
    output = subprocess.check_output(
        [unitd, '--version'], stderr=subprocess.STDOUT
    )

    if re.search('--no-regex', output.decode()):
        return False

    return True
