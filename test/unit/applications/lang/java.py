import glob
import os
import pytest
import shutil
import subprocess

from unit.applications.proto import TestApplicationProto
from conftest import option


class TestApplicationJava(TestApplicationProto):
    def load(self, script, name='app', **kwargs):
        app_path = self.temp_dir + '/java'
        web_inf_path = app_path + '/WEB-INF/'
        classes_path = web_inf_path + 'classes/'
        script_path = option.test_dir + '/java/' + script + '/'

        if not os.path.isdir(app_path):
            os.makedirs(app_path)

        src = []

        for f in os.listdir(script_path):
            file_path = script_path + f

            if f.endswith('.java'):
                src.append(file_path)
                continue

            if f.startswith('.') or f == 'Makefile':
                continue

            if os.path.isdir(file_path):
                if f == 'WEB-INF':
                    continue

                shutil.copytree(file_path, app_path + '/' + f)
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

            classpath = self.pardir + '/build/tomcat-servlet-api-9.0.13.jar'

            ws_jars = glob.glob(
                self.pardir + '/build/websocket-api-java-*.jar'
            )

            if not ws_jars:
                pytest.fail('websocket api jar not found.')

            javac = [
                'javac',
                '-encoding',   'utf-8',
                '-d',          classes_path,
                '-classpath',  classpath + ':' + ws_jars[0],
            ]
            javac.extend(src)

            try:
                process = subprocess.Popen(javac, stderr=subprocess.STDOUT)
                process.communicate()

            except:
                pytest.fail('Cann\'t run javac process.')

        self._load_conf(
            {
                "listeners": {"*:7080": {"pass": "applications/" + script}},
                "applications": {
                    script: {
                        "unit_jars": self.pardir + '/build',
                        "type": 'java',
                        "processes": {"spare": 0},
                        "working_directory": script_path,
                        "webapp": app_path,
                    }
                },
            },
            **kwargs
        )
