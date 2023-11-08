from unit.applications.proto import ApplicationProto
from unit.option import option


class ApplicationPerl(ApplicationProto):
    def __init__(self, application_type='perl'):
        self.application_type = application_type

    def load(self, script, name='psgi.pl', **kwargs):
        script_path = f'{option.test_dir}/perl/{script}'

        self._load_conf(
            {
                "listeners": {"*:8080": {"pass": f"applications/{script}"}},
                "applications": {
                    script: {
                        "type": self.get_application_type(),
                        "processes": {"spare": 0},
                        "working_directory": script_path,
                        "script": f'{script_path}/{name}',
                    }
                },
            },
            **kwargs,
        )
