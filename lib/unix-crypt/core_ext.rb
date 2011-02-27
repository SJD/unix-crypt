# encoding: utf-8

module UnixCrypt

    module CoreExt

        module StringExt

            SET_SIZES = {
                /[a-z]/ => 26,
                /[A-Z]/ => 26,
                /[0-9]/ => 10,
                /[^\w]/ => 32
            }.freeze

            def unixcrypt_keyspace
                set_size = 0
                SET_SIZES.each_pair {|set, size| set_size += size if self =~ set}
                set_size ** length
            end

            String.class_eval do
                def self.digest(obj)
                    self.new(obj)
                end
            end

        end # module StringExt

    end # module CoreExt

    String.send(:include, UnixCrypt::CoreExt::StringExt)

end # module UnixCrypt
