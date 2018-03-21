app = Proc.new do |env|
    file = File.open('file', 'r')
    ['200', {'Content-Length' => '5'}, file]
end

run app
