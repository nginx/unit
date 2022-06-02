app = Proc.new do |env|
    env['rack.errors'].write('Error in application')
    env['rack.errors'].flush
    env['rack.errors'].close
    ['200', {'Content-Length' => '0'}, ['']]
end

run app
