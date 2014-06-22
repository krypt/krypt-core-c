$:.unshift File.expand_path('../lib', __FILE__)

require 'krypt/core/version'

Gem::Specification.new do |s|

  s.name = 'krypt-core'
  s.version = Krypt::Core::VERSION

  s.author = 'Hiroshi Nakamura, Martin Bosslet'
  s.email = 'Martin.Bosslet@gmail.com'
  s.homepage = 'https://github.com/krypt/krypt-core-c'
  s.summary = 'C implementation of the krypt-core API'
  s.description = 'krypt-core API for C(++)-based Rubies' 

  s.required_ruby_version     = '>= 1.9.3'

  s.extensions << 'ext/krypt/core/extconf.rb'
  s.files = %w(Rakefile LICENSE README.rdoc) + Dir.glob('{ext,lib}/**/*')
  s.require_path = "lib"
  s.license = 'MIT'

  s.platform = 'ruby'
  s.add_dependency 'binyo', '0.0.2'
  s.add_dependency 'krypt-provider-openssl', '0.0.2'

end
