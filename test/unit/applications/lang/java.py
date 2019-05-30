import os
import shutil
from subprocess import Popen
from unit.applications.proto import TestApplicationProto


class TestApplicationJava(TestApplicationProto):
    def load(self, script, name='app'):

        app_path = self.testdir + '/java'
        web_inf_path = app_path + '/WEB-INF/'
        classes_path = web_inf_path + 'classes/'

        script_path = self.current_dir + '/java/' + script + '/'

        if not os.path.isdir(app_path):
            os.makedirs(app_path)

        src = []

        for f in os.listdir(script_path):
            if f.endswith('.java'):
                src.append(script_path + f)
                continue

            if f.startswith('.') or f == 'Makefile':
                continue

            if os.path.isdir(script_path + f):
                if f == 'WEB-INF':
                    continue

                shutil.copytree(script_path + f, app_path + '/' + f)
                continue

            if f == 'web.xml':
                if not os.path.isdir(web_inf_path):
                    os.makedirs(web_inf_path)

                shutil.copy2(script_path + f, web_inf_path)
            else:
                shutil.copy2(script_path + f, app_path)

        if src:
            if not os.path.isdir(classes_path):
                os.makedirs(classes_path)

            tomcat_jar = self.pardir + '/build/tomcat-servlet-api-9.0.13.jar'

            javac = [
                'javac',
                '-encoding',   'utf-8',
                '-d',          classes_path,
                '-classpath',  tomcat_jar,
            ]
            javac.extend(src)

            process = Popen(javac)
            process.communicate()

        self._load_conf(
            {
                "listeners": {"*:7080": {"pass": "applications/" + script}},
                "applications": {
                    script: {
                        "unit_jars": self.pardir + '/build',
                        "type": "java",
                        "processes": {"spare": 0},
                        "working_directory": script_path,
                        "webapp": app_path,
                    }
                },
            }
        )
