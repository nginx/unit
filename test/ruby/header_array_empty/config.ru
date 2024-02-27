app = Proc.new do |env|
    ['200', {
        'x-array' => [],
    }, []]
end

run app
