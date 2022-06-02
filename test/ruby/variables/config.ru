app = Proc.new do |env|
    body = env['rack.input'].read
    version = env['rack.version'].join('')

    ['200', {
        'Content-Type' => env['CONTENT_TYPE'],
        'Content-Length' => body.length.to_s,
        'Request-Method' => env['REQUEST_METHOD'],
        'Request-Uri' => env['REQUEST_URI'],
        'Http-Host' => env['HTTP_HOST'],
        'Script-Name' => env['SCRIPT_NAME'],
        'Server-Protocol' => env['SERVER_PROTOCOL'],
        'Server-Software' => env['SERVER_SOFTWARE'],
        'Custom-Header' => env['HTTP_CUSTOM_HEADER'],
        'Rack-Version' => version,
        'Rack-Url-Scheme' => env['rack.url_scheme'],
        'Rack-Multithread' => env['rack.multithread'].to_s,
        'Rack-Multiprocess' => env['rack.multiprocess'].to_s,
        'Rack-Run-Once' => env['rack.run_once'].to_s,
        'Rack-Hijack-Q' => env['rack.hijack?'].to_s,
        'Rack-Hijack' => env['rack.hijack'].to_s,
        'Rack-Hijack-IO' => env['rack.hijack_io'].to_s
    }, [body]]
end

run app
