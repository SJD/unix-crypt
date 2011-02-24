# encoding: utf-8

require 'base64'

spec = Gem::Specification.new do |s|
    s.name = 'unix-crypt'
    s.version = '1.0.2'
    s.summary = "Performs the UNIX crypt(3) algorithm using DES, MD5, SHA256 or SHA512"
    s.description = %{Performs the UNIX crypt(3) algorithm using DES (standard 13 character passwords), MD5 (starting with $1$), SHA256 (starting with $5$) and SHA512 (starting with $6$)}
    s.require_path = 'lib'
    s.files = [
        "lib/unix-crypt.rb",
        "lib/unix-crypt/core_ext.rb",
        "lib/unix-crypt/base.rb",
        "lib/unix-crypt/des.rb",
        "lib/unix-crypt/md5.rb",
        "lib/unix-crypt/sha.rb",
        "test/unix_crypt_test.rb"
    ]
    s.test_files = [
        "test/unix_crypt_test.rb"
    ]
    s.homepage = "https://github.com/SJD/unix-crypt"
    s.authors = ["Roger Nesbitt", "Sam Duncan"]
    s.email = ["roger@seriousorange.com", Base64.decode64("Z2l0aHViQHBvcnQ4MC5jby5ueg==\n")]
end