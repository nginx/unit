app = Proc.new do |env|
    delay = env['HTTP_X_DELAY'].to_f

    sleep(delay)

    ['200', {
        'Content-Length' => 0.to_s,
        'Rack-Multithread' => env['rack.multithread'].to_s,
        'X-Thread' => Thread.current.object_id.to_s
    }, []]
end

run app
