app = Proc.new |env|
    ['200', {'Content-Length' => '0'}, ['']]
end

run app
