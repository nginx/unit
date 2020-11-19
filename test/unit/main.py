import pytest
from conftest import option


class TestUnit():
    @classmethod
    def setup_class(cls, complete_check=True):
        def check():
            missed = []

            # check modules

            if 'modules' in cls.prerequisites:
                available_modules = list(option.available['modules'].keys())

                for module in cls.prerequisites['modules']:
                    if module in available_modules:
                        continue

                    missed.append(module)

            if missed:
                pytest.skip('Unit has no ' + ', '.join(missed) + ' module(s)')

            # check features

            if 'features' in cls.prerequisites:
                available_features = list(option.available['features'].keys())

                for feature in cls.prerequisites['features']:
                    if feature in available_features:
                        continue

                    missed.append(feature)

            if missed:
                pytest.skip(', '.join(missed) + ' feature(s) not supported')

        if complete_check:
            check()
        else:
            return check
