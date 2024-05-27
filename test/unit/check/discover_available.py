import subprocess
import sys

from unit.check.chroot import check_chroot
from unit.check.go import check_go
from unit.check.isolation import check_isolation
from unit.check.njs import check_njs
from unit.check.node import check_node
from unit.check.regex import check_regex
from unit.check.tls import check_openssl
from unit.check.unix_abstract import check_unix_abstract
from unit.log import Log
from unit.option import option


def discover_available(unit):
    output_version = subprocess.check_output(
        [unit['unitd'], '--version'], stderr=subprocess.STDOUT
    ).decode()

    option.configure_flag['asan'] = '-fsanitize=address' in output_version

    # wait for controller start

    if Log.wait_for_record(r'controller started') is None:
        Log.print_log()
        sys.exit("controller didn't start")

    # discover modules from log file

    for module in Log.findall(r'module: ([a-zA-Z]+) (.*) ".*"$'):
        versions = option.available['modules'].setdefault(module[0], [])
        if module[1] not in versions:
            versions.append(module[1])

    # discover modules using check

    option.available['modules']['go'] = check_go()
    option.available['modules']['njs'] = check_njs(output_version)
    option.available['modules']['node'] = check_node()
    option.available['modules']['openssl'] = check_openssl(output_version)
    option.available['modules']['regex'] = check_regex(output_version)

    # Discover features using check. Features should be discovered after
    # modules since some features can require modules.

    option.available['features']['chroot'] = check_chroot()
    option.available['features']['isolation'] = check_isolation()
    option.available['features']['unix_abstract'] = check_unix_abstract()
