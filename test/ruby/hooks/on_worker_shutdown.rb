require 'securerandom'

on_worker_shutdown do
    File.write("./cookie_worker_shutdown.#{SecureRandom.hex}", "shutdown")
end
