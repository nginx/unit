app = Proc.new do |env|
    ['200', {
        'x-array' => [nil],
    }, []]
end

run app
