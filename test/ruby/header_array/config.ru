app = Proc.new do |env|
    ['200', {
        'x-array' => ['name=value', '', 'value', 'av'],
    }, []]
end

run app
