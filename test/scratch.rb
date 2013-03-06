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

provider = Krypt::Provider::OpenSSL.new

Benchmark.bmbm do |results|
  results.report('krypt-pbkdf2-c') do
    pbkdf = Krypt::PBKDF2.new(Krypt::Digest::SHA1.new)
    pbkdf.generate(key, salt, iter, len)
  end
  results.report('krypt-pbkdf2-ffi') do
    pbkdf = Krypt::PBKDF2.new(Krypt::Digest.new("SHA1", p))
    pbkdf.generate(key, salt, iter, len)
  end
  results.report('openssl-pbkdf2') do
    md = OpenSSL::Digest.new("SHA1")
    OpenSSL::PKCS5.pbkdf2_hmac_sha1(key, salt, iter, len)
  end
end

Benchmark.bm do |bm|

  n = 100000

  bm.report("Krypt::Digest C empty string") do
    n.times do
      digest = Krypt::Digest::new("SHA1").digest("")
    end
  end

  bm.report("Krypt::Digest::SHA1 C empty string") do
    n.times do
      digest = Krypt::Digest::SHA1.new.digest("")
    end
  end

  bm.report("Krypt::Digest FFI empty string") do
    n.times do
      digest = Krypt::Digest::new("SHA1", p).digest("")
    end
  end

  bm.report("OpenSSL::Digest empty string") do
    n.times do
      digest = OpenSSL::Digest.new("SHA1").digest("")
    end
  end

  n = 1_000_000

  bm.report("Krypt::Digest::SHA1 million times 'a'") do
    digest = Krypt::Digest::SHA1.new
    n.times do
      digest << "a"
    end
    s = digest.digest
  end

  bm.report("Krypt::Digest FFI million times 'a'") do
    digest = Krypt::Digest.new("SHA1", p)
    n.times do
      digest << "a"
    end
    s = digest.digest
  end

  bm.report("OpenSSL::Digest::SHA1 million times 'a'") do
    digest = OpenSSL::Digest::SHA1.new
    n.times do
      digest << "a"
    end
    s = digest.digest
  end

  n = 1000

  bm.report("Krypt::Digest::SHA1 million times 'a' at once") do
    n.times do
      digest = Krypt::Digest::SHA1.new
      digest << ("a" * 1_000_000)
      s = digest.digest
    end
  end

  bm.report("Krypt::Digest FFI million times 'a' at once") do
    n.times do
      digest = Krypt::Digest.new("SHA1", p)
      digest << ("a" * 1_000_000)
      s = digest.digest
    end
  end

  bm.report("OpenSSL::Digest::SHA1 million times 'a' at once") do
    n.times do
      digest = OpenSSL::Digest::SHA1.new
      digest << ("a" * 1_000_000)
      s = digest.digest
    end
  end
end
