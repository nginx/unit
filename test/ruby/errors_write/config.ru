app = Proc.new do |env|
    env['rack.errors'].write('Error in application')
    ['200', {'Content-Length' => '0'}, ['']]
end

run app
