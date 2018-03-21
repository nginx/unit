app = Proc.new do |env|
    body = ''
    env['rack.input'].each do |value|
        body += value
    end
    ['200', {
        'Content-Length' => body.length.to_s
    }, [body]]
end

run app
