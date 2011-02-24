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

            def strength
                set_size = 0
                SET_SIZES.each_pair {|set, size| set_size += size if self =~ set}
                key_space = set_size ** length
                # brute force 1000 per second
                key_space.to_f / 1000
            end

        end # module StringExt

    end # module CoreExt

    String.send(:include, UnixCrypt::CoreExt::StringExt)

end # module UnixCrypt