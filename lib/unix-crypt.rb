# encoding: utf-8

require 'unix-crypt/core_ext'
require 'unix-crypt/base'
require 'unix-crypt/des'
require 'unix-crypt/md5'
require 'unix-crypt/sha'

module UnixCrypt

    CRYPT_CHARS = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".freeze
    DEFAULT_MIN_ROUNDS = 1000
    DEFAULT_MAX_ROUNDS = 999_999_999
    DEFAULT_ROUNDS = 5000
    DEFAULT_SALT_LENGTH = 16

    IDENTIFIER_MAPPINGS = {
        nil => UnixCrypt::DES,
        UnixCrypt::MD5.identifier.to_s => UnixCrypt::MD5,
        UnixCrypt::SHA256.identifier.to_s => UnixCrypt::SHA256,
        UnixCrypt::SHA512.identifier.to_s => UnixCrypt::SHA512
    }.freeze

    module_eval do
        begin
            require 'securerandom'
            def self.random(*args); SecureRandom.random_number(*args); end
            SECURE_RANDOM = true
        rescue LoadError
            def self.random(*args); Kernel.rand(*args) end
            SECURE_RANDOM = false
        end
    end unless defined?(SECURE_RANDOM)

    def self.secure_random?
        SECURE_RANDOM
    end

    def self.valid?(password, target)
        m = target.match(/\A\$([156])\$(?:rounds=(\d+)\$)?(.+)\$(.+)/)
        id, salt, rounds, target = case m
            when nil then [nil, target, nil, target]
                else [m[1], m[3], m[2] && m[2].to_i, m[4]]
        end

        pwhash = IDENTIFIER_MAPPINGS[id].hash(password, salt, rounds && rounds.to_i)
        pwhash == target
    end

    def self.make_salt(length=16)
        length.times.collect { CRYPT_CHARS[ random( CRYPT_CHARS.length ) ] }.join("")
    end

end # module UnixCrypt
