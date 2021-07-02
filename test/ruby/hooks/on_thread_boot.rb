require 'securerandom'

on_thread_boot do
    File.write("./cookie_thread_boot.#{SecureRandom.hex}", "booted")
end
