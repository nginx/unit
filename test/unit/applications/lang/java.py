import glob
import os
import shutil
import subprocess

import pytest
from unit.applications.proto import ApplicationProto
from unit.option import option


class ApplicationJava(ApplicationProto):
    def __init__(self, application_type='java'):
        self.application_type = application_type

    def prepare_env(self, script):
        app_path = f'{option.temp_dir}/java'
        web_inf_path = f'{app_path}/WEB-INF/'
        classes_path = f'{web_inf_path}classes/'
        script_path = f'{option.test_dir}/java/{script}/'

        if not os.path.isdir(app_path):
            os.makedirs(app_path)

        src = []

        for f in os.listdir(script_path):
            file_path = f'{script_path}{f}'

            if f.endswith('.java'):
                src.append(file_path)
                continue

            if f.startswith('.') or f == 'Makefile':
                continue

            if os.path.isdir(file_path):
                if f == 'WEB-INF':
                    continue

                shutil.copytree(file_path, f'{app_path}/{f}')
                continue

            if f == 'web.xml':
                if not os.path.isdir(web_inf_path):
                    os.makedirs(web_inf_path)

                shutil.copy2(file_path, web_inf_path)
            else:
                shutil.copy2(file_path, app_path)

        if src:
            if not os.path.isdir(classes_path):
                os.makedirs(classes_path)

            classpath = (
                f'{option.current_dir}/build/tomcat-servlet-api-9.0.98.jar'
            )

            ws_jars = glob.glob(
                f'{option.current_dir}/build/websocket-api-java*.jar'
            )

            if not ws_jars:
                pytest.fail('websocket api jar not found.')

            javac = [
                'javac',
                '-target',
                '8',
                '-source',
                '8',
                '-nowarn',
                '-encoding',
                'utf-8',
                '-d',
                classes_path,
                '-classpath',
                f'{classpath}:{ws_jars[0]}',
            ]
            javac.extend(src)

            if option.detailed:
                print(f'\n$ {" ".join(javac)}')

            try:
                subprocess.check_output(javac, stderr=subprocess.STDOUT)

            except KeyboardInterrupt:
                raise

            except subprocess.CalledProcessError:
                pytest.fail("Can't run javac process.")

    def load(self, script, **kwargs):
        self.prepare_env(script)

        script_path = f'{option.test_dir}/java/{script}/'
        self._load_conf(
            {
                "listeners": {"*:8080": {"pass": f"applications/{script}"}},
                "applications": {
                    script: {
                        "unit_jars": f'{option.current_dir}/build',
                        "type": self.get_application_type(),
                        "processes": {"spare": 0},
                        "working_directory": script_path,
                        "webapp": f'{option.temp_dir}/java',
                    }
                },
            },
            **kwargs,
        )
