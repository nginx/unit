app = Proc.new do |env|
    body = ''
    buf = ''
    loop do
        buf = env['rack.input'].gets
        break if buf == nil
        body += buf
    end
    ['200', {
        'Content-Length' => body.length.to_s
    }, [body]]
end

run app
