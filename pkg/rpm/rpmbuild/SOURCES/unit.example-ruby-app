app = Proc.new do |env|
    ['200', {
        'Content-Type' => 'text/plain',
    }, ["Hello from Unit running with Ruby #{RUBY_VERSION}!\n\n"]]
end

run app
