# encoding: UTF-8

require 'krypt'
require 'benchmark'
require 'openssl'

iter  = 4096
key   = "secretkey"
salt  = "salt"
len   = 20 
#data    = "Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum."
#


Benchmark.bmbm do |results|
  results.report('krypt-pbkdf2') do
    pbkdf = Krypt::PBKDF2.new(Krypt::Digest::SHA1.new)
    pbkdf.generate(key, salt, iter, len)
  end
  results.report('openssl-pbkdf2') do
    md = OpenSSL::Digest.new("SHA1")
    OpenSSL::PKCS5.pbkdf2_hmac_sha1(key, salt, iter, len)
  end
end

