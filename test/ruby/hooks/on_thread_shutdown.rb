require 'securerandom'

on_thread_shutdown do
    File.write("./cookie_thread_shutdown.#{SecureRandom.hex}", "shutdown")
end
