# encoding: utf-8

module UnixCrypt

    class Base

        private

        def self._min_rounds
            @min_rounds ||= DEFAULT_MIN_ROUNDS
        end

        def self._max_rounds
            @max_rounds ||= DEFAULT_MAX_ROUNDS
        end

        def self._default_rounds
            @default_rounds ||= DEFAULT_ROUNDS
        end

        def self._salt_length
            @salt_length ||= DEFAULT_SALT_LENGTH
        end

        def self._salt
            UnixCrypt.make_salt(_salt_length)
        end

        protected

        def self.clamp_rounds(rounds)
            begin
                rounds.nil? \
                    ? _default_rounds : (rounds.to_i < _min_rounds \
                        ? _min_rounds : (rounds.to_i > _max_rounds \
                            ? _max_rounds : rounds.to_i))
            rescue
                _default_rounds
            end
        end

        def self.base64encode(input)
            input = input.bytes.to_a
            output = ""
            byte_indexes.each do |i3, i2, i1|
                b1, b2, b3 = i1 && input[i1] || 0, i2 && input[i2] || 0, i3 && input[i3] || 0
                output << CRYPT_CHARS[b1 & 0b00111111] << CRYPT_CHARS[((b1 & 0b11000000) >> 6) | ((b2 & 0b00001111) << 2)] << CRYPT_CHARS[((b2 & 0b11110000) >> 4) | ((b3 & 0b00000011) << 4)]  << CRYPT_CHARS[ (b3 & 0b11111100) >> 2]
            end

            remainder = 3 - (length % 3)
            remainder = 0 if remainder == 3
            output[0..-1-remainder]
        end

        public

        def self.build(password, salt, rounds=nil)
            if identifier.nil?
                "#{hash(password, salt, rounds)}"
            elsif clamp_rounds(rounds) == _default_rounds
                "$#{identifier}$#{salt}$#{hash(password, salt, rounds)}"
            else
                "$#{identifier}$rounds=#{clamp_rounds(rounds)}$#{salt}$#{hash(password, salt, rounds)}"
            end
        end

        def self.mkpasswd(password, opts={})
            defaults = {:salt => _salt, :rounds => _default_rounds}
            opts = defaults.merge(opts) {|key, default, passed| passed.nil? ? default : passed }
            build(password, opts[:salt], opts[:rounds])
        end

    end # class Base

end # module UnixCrypt
