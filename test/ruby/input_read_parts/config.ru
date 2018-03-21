app = Proc.new do |env|
    body = env['rack.input'].read(4)
    body += env['rack.input'].read(4)
    body += env['rack.input'].read(1)
    ['200', {
        'Content-Length' => body.length.to_s
    }, [body]]
end

run app
