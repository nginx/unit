app = Proc.new do |env|
    ['200', {
        'Content-Length' => '0',
        'Query-String' => env['QUERY_STRING']
    }, ['']]
end

run app
