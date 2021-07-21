require 'securerandom'

@mutex = Mutex.new

on_thread_shutdown do
    @mutex.synchronize do
        File.write("./cookie_thread_shutdown.#{SecureRandom.hex}", "shutdown")
    end
end
