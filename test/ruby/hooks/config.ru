app = Proc.new do |env|
    ['200', {
        'Content-Length' => '0'
    }, ['']]
end

run app
