import re


def check_njs(output_version):
    if re.search('--njs', output_version):
        return True
