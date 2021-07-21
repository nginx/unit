require 'securerandom'

@mutex = Mutex.new

on_thread_boot do
    @mutex.synchronize do
        File.write("./cookie_thread_boot.#{SecureRandom.hex}", "booted")
    end
end
