app = Proc.new do |env|
    body = env['rack.input'].gets
    env['rack.input'].close
    ['200', {
        'Content-Length' => body.length.to_s
    }, [body]]
end

run app
