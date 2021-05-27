import os
import subprocess


def check_go(current_dir, temp_dir, test_dir):
    if not os.path.exists(temp_dir + '/go'):
        os.mkdir(temp_dir + '/go')

    env = os.environ.copy()
    env['GOPATH'] = current_dir + '/build/go'
    env['GO111MODULE'] = 'auto'

    try:
        process = subprocess.Popen(
            [
                'go',
                'build',
                '-o',
                temp_dir + '/go/app',
                test_dir + '/go/empty/app.go',
            ],
            env=env,
        )
        process.communicate()

        if process.returncode == 0:
            return True

    except KeyboardInterrupt:
        raise

    except:
        return None
