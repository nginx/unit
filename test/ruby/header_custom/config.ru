app = Proc.new do |env|
    ['200', {
        'Content-Length' => '0',
        'Custom-Header' => env['rack.input'].read
    }, []]
end

run app
