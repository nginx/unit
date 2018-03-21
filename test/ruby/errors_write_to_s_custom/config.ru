app = Proc.new do |env|

    class Custom
        def to_s()
            nil
        end
    end

    e = Custom.new()

    env['rack.errors'].write(e)
    ['200', {'Content-Length' => '0'}, ['']]
end

run app
