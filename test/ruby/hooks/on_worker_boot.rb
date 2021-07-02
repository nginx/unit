require 'securerandom'

on_worker_boot do
    File.write("./cookie_worker_boot.#{SecureRandom.hex}", "booted")
end
