app = Proc.new do |env|
    ['200', {
        'Content-Length' => '0',
        'rack.header' => 'hello'
    }, ['']]
end

run app
