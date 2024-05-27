app = Proc.new do |env|
    io = IO.new(0, 'r')
    ['200', {'Content-Length' => '0'}, io]
end

run app
