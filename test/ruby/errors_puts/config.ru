app = Proc.new do |env|
    env['rack.errors'].puts('Error in application')
    ['200', {'Content-Length' => '0'}, ['']]
end

run app
