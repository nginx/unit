app = Proc.new do |env|
    env['rack.errors'].puts(1234567890)
    ['200', {'Content-Length' => '0'}, ['']]
end

run app
