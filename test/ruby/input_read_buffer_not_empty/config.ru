app = Proc.new do |env|
    body = 'blah'
    env['rack.input'].read(nil, body)
    ['200', {
        'Content-Length' => body.length.to_s
    }, [body]]
end

run app
