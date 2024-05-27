import re


def check_njs(output_version):
    return re.search('--njs', output_version)
