import re


def check_regex(output_version):
    if re.search('--no-regex', output_version):
        return False

    return True
