app = Proc.new do |env|
    env['rack.errors'].write(1234567890)
    ['200', {'Content-Length' => '0'}, ['']]
end

run app
