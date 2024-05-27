require 'securerandom'

@mutex = Mutex.new

on_worker_boot do
    File.write("./cookie_worker_boot.#{SecureRandom.hex}", "worker booted")
end

on_thread_boot do
    @mutex.synchronize do
        File.write("./cookie_thread_boot.#{SecureRandom.hex}", "thread booted")
    end
end
