app = Proc.new do |env|
    ['200', {
        'X-Copyright' => RUBY_COPYRIGHT,
        'X-Description' => RUBY_DESCRIPTION,
        'X-Engine' => RUBY_ENGINE,
        'X-Engine-Version' => RUBY_ENGINE_VERSION,
        'X-Patchlevel' => RUBY_PATCHLEVEL.to_s,
        'X-Platform' => RUBY_PLATFORM,
        'X-Release-Date' => RUBY_RELEASE_DATE,
        'X-Revision' => RUBY_REVISION.to_s,
        'X-Version' => RUBY_VERSION,
    }, []]
end

run app
