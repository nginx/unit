app = Proc.new do |env|
    ['200', {}, []]
end

run app
