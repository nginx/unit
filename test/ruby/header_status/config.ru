app = Proc.new do |env|
    ['200', {
        'Content-Length' => '0',
        'Status' => '200'
    }, []]
end

run app
