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
        'libraries': ["-lunit"]
    }]
}
