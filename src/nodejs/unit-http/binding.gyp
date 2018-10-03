{
    'targets': [{
        'target_name': "unit-http",
        'sources': ["unit.cpp", "addon.cpp"],
        'include_dirs': [
            "<!(echo $UNIT_SRC_PATH)"
        ],
        'libraries': [
            "<!(echo $UNIT_LIB_STATIC_PATH)"
        ]
    }]
}
