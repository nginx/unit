app = Proc.new do |env|
    ['200', {'Content-Length' => '10'}, ['0123', '4567', '89']]
end

run app
