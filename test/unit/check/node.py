import subprocess
from pathlib import Path

from unit.option import option


def check_node():
    if not Path(f'{option.current_dir}/node/node_modules').exists():
        return False

    try:
        v_bytes = subprocess.check_output(['/usr/bin/env', 'node', '-v'])

        return [str(v_bytes, 'utf-8').lstrip('v').rstrip()]

    except subprocess.CalledProcessError:
        return False
