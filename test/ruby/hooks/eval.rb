require 'securerandom'

File.write("./cookie_eval.#{SecureRandom.hex}", "evaluated")
