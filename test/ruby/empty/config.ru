app = Proc.new do |env|
    body = env['rack.input'].gets
    #body += env['rack.input'].gets
    ['200', {
        'Content-Length' => body.length.to_s
    }, [body]]
end

run app
