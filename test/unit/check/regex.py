import re


def check_regex(output_version):
    return not re.search('--no-regex', output_version)
