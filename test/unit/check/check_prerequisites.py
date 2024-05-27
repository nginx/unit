import pytest

from unit.option import option


def check_prerequisites(prerequisites):
    if 'privileged_user' in prerequisites:
        if prerequisites['privileged_user'] and not option.is_privileged:
            pytest.skip(
                'privileged user required',
                allow_module_level=True,
            )
        elif not prerequisites['privileged_user'] and option.is_privileged:
            pytest.skip(
                'unprivileged user required',
                allow_module_level=True,
            )

    missed = []

    # check modules

    if 'modules' in prerequisites:
        available = option.available['modules']

        for module in prerequisites['modules']:
            if module in available and available[module]:
                continue

            missed.append(module)

    if missed:
        pytest.skip(
            f'Unit has no {", ".join(missed)} module(s)',
            allow_module_level=True,
        )

    # check features

    if 'features' in prerequisites:
        available = option.available['features']
        require = prerequisites['features']

        for feature in require:
            avail_feature = available[feature]

            if feature in available and avail_feature:
                if isinstance(require[feature], list) and isinstance(
                    avail_feature, dict
                ):
                    avail_keys = avail_feature.keys()

                    for key in require[feature]:
                        if key not in avail_keys:
                            missed.append(f'{feature}/{key}')
                continue

            missed.append(feature)

    if missed:
        pytest.skip(
            f'{", ".join(missed)} feature(s) not supported',
            allow_module_level=True,
        )
