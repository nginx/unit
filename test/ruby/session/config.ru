app = Proc.new do |env|
    env['rack.session'].clear
    [200, {}, []]
end

run app
