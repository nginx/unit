app = Proc.new do |env|
    ['200', {
        'Content-Length' => '0',
        'X-Enc' => Encoding.default_external.to_s,
    }, ['']]
end

run app
