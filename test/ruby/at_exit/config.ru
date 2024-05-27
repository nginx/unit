app = Proc.new do |env|
    at_exit do
      env['rack.errors'].puts('At exit called.')
    end
    ['200', {'Content-Length' => '0'}, ['']]
end

run app
