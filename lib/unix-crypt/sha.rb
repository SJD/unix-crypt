# encoding: utf-8

require 'digest'

module UnixCrypt

    class SHABase < UnixCrypt::Base

        @default_rounds = 5000
        @salt_length = 16

        def self.hash(password, salt, rounds=nil)
            rounds = clamp_rounds(rounds)
            salt = salt[0.._salt_length]

            b = digest.digest("#{password}#{salt}#{password}")

            a_string = password + salt + b * (password.length/length) + b[0...password.length % length]

            password_length = password.length
            while password_length > 0
                a_string += (password_length & 1 != 0) ? b : password
                password_length >>= 1
            end

            input = a = digest.digest(a_string)

            dp = digest.digest(password * password.length)
            p = dp * (password.length/length) + dp[0...password.length % length]

            ds = digest.digest(salt * (16 + a.bytes.first))
            s = ds * (salt.length/length) + ds[0...salt.length % length]

            rounds.times do |index|
                c_string = ((index & 1 != 0) ? p : input)
                c_string += s unless index % 3 == 0
                c_string += p unless index % 7 == 0
                c_string += ((index & 1 != 0) ? input : p)
                input = digest.digest(c_string)
            end

            base64encode(input)
        end

    end # end class SHABase

    class SHA256 < SHABase

        def self.digest; Digest::SHA256; end
        def self.length; 32; end
        def self.identifier; 5; end

        def self.byte_indexes
            [[0, 10, 20], [21, 1, 11], [12, 22, 2], [3, 13, 23], [24, 4, 14], [15, 25, 5], [6, 16, 26], [27, 7, 17], [18, 28, 8], [9, 19, 29], [nil, 31, 30]]
        end

    end # class SHA256

    class SHA512 < SHABase
        def self.digest; Digest::SHA512; end
        def self.length; 64; end
        def self.identifier; 6; end
        def self.byte_indexes
            [[0, 21, 42], [22, 43, 1], [44, 2, 23], [3, 24, 45], [25, 46, 4], [47, 5, 26], [6, 27, 48], [28, 49, 7], [50, 8, 29], [9, 30, 51], [31, 52, 10],
            [53, 11, 32], [12, 33, 54], [34, 55, 13], [56, 14, 35], [15, 36, 57], [37, 58, 16], [59, 17, 38], [18, 39, 60], [40, 61, 19], [62, 20, 41], [nil, nil, 63]]
        end

    end # class SHA512
    
end # module UnixCrypt
