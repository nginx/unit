import os
import subprocess


def check_go(current_dir, temp_dir, test_dir):
    if not os.path.exists(temp_dir + '/go'):
        os.mkdir(temp_dir + '/go')

    env = os.environ.copy()
    env['GOPATH'] = current_dir + '/build/go'
    env['GO111MODULE'] = 'auto'

    try:
        process = subprocess.run(
            [
                'go',
                'build',
                '-o',
                temp_dir + '/go/app',
                test_dir + '/go/empty/app.go',
            ],
            env=env,
            stderr=subprocess.STDOUT,
            stdout=subprocess.PIPE,
        )

        if process.returncode == 0:
            return True

    except KeyboardInterrupt:
        raise

    except subprocess.CalledProcessError:
        return None
