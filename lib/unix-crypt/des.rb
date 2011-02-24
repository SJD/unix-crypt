# encoding: utf-8

module UnixCrypt

    # someone might want to implement DES a la GNU crypt.c in ruby
    # meanwhile this is just a standardisation of the interface
    class DES < UnixCrypt::Base

        @default_rounds = 1
        @salt_length = 2

        def self.digest; String; end
        def self.length; 13; end
        def self.identifier; end

        def self.hash(password, salt, rounds=nil)
            rounds = clamp_rounds(rounds)
            salt = salt[0.._salt_length]

            input = self.digest.new(password)
            rounds.times do |index|
                input = input.crypt(salt)
            end

            input
        end

    end # class DES

end # module UnixCrypt