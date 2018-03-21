app = Proc.new do |env|
    ['200', {
        'Content-Length' => '0',
        'Server-Port' => env['SERVER_PORT']
    }, ['']]
end

run app
