{
    'targets': [{
        'target_name': "unit-http",
        'cflags!': [ '-fno-exceptions' ],
        'cflags_cc!': [ '-fno-exceptions' ],
        'conditions': [
            ['OS=="mac"', {
              'xcode_settings': {
                'GCC_ENABLE_CPP_EXCEPTIONS': 'YES'
              }
            }]
        ],
        'sources': ["unit.cpp", "addon.cpp"],
        'include_dirs': [
            "<!(echo $UNIT_SRC_PATH)", "<!(echo $UNIT_BUILD_PATH/include)"
        ],
        'libraries': [
            "<!(echo $UNIT_LIB_STATIC_PATH)"
        ]
    }]
}
