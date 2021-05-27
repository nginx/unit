import os
import subprocess


def check_node(current_dir):
    if not os.path.exists(current_dir + '/node/node_modules'):
        return None

    try:
        v_bytes = subprocess.check_output(['/usr/bin/env', 'node', '-v'])

        return [str(v_bytes, 'utf-8').lstrip('v').rstrip()]

    except subprocess.CalledProcessError:
        return None
