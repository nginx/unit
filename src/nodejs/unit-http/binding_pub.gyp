{
    'targets': [{
        'target_name': "unit-http",
        'cflags!': [ '-fno-exceptions' ],
        'cflags_cc!': [ '-fno-exceptions' ],
        'conditions': [
            ['OS=="mac"', {
              'xcode_settings': {
                'GCC_ENABLE_CPP_EXCEPTIONS': 'YES'
              },
              'conditions': [
                  [ 'target_arch=="arm64"', {
                      'include_dirs': [
                          '/opt/homebrew/include'
                      ],
                      'libraries' : [
                          '-L/opt/homebrew/lib',
                          '-lunit'
                      ],
                  }],
                  ['target_arch=="x64"', {
                      'include_dirs': [
                          '/usr/local/include',
                      ],
                      'libraries' : [
                          '-L/usr/local/lib',
                          '-lunit'
                      ],
                  }]
              ]}
            ]],
        'sources': ["unit.cpp", "addon.cpp"],
        'libraries': ["-lunit"]
    }]
}
