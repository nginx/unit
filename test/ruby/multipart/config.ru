app = Proc.new do |env|
    [200, {
        'x-multipart-buffer' => env['rack.multipart.buffer_size'].to_s
    }, []]
end

run app
