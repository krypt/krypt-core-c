version = '0.0.1'

Gem::Specification.new do |s|

  s.name = 'krypt-core'
  s.version = version

  s.author = 'Hiroshi Nakamura, Martin Bosslet'
  s.email = 'Martin.Bosslet@gmail.com'
  s.homepage = 'https://github.com/krypt/krypt-core-c'
  s.summary = 'C implementation of the krypt-core API'
  s.description = 'krypt-core API for C(++)-based Rubies' 

  s.required_ruby_version     = '>= 1.9.3'

  s.extensions << 'ext/krypt/core/extconf.rb'
  s.files = %w(LICENSE) + Dir.glob('{bin,ext,lib,spec,test}/**/*')
  s.test_files = Dir.glob('test/**/test_*.rb')
  s.require_path = "lib"
  s.license = 'MIT'

  s.platform = 'ruby'
  s.add_dependency 'binyo', version
  s.add_dependency 'krypt-provider-openssl', version

end
