app = Proc.new do |env|
    env['rack.input'].read
    env['rack.input'].rewind
    body = env['rack.input'].read
    ['200', {'Content-Length' => body.length.to_s}, [body]]
end

run app
