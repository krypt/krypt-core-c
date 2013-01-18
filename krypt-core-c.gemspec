Gem::Specification.new do |s|
  s.name = 'krypt-core-c'
  s.version = '0.0.1'
  s.author = 'Hiroshi Nakamura, Martin Bosslet'
  s.email = 'Martin.Bosslet@gmail.com'
  s.homepage = 'https://github.com/krypt/krypt-core-c'
  s.summary = 'C implementation of the krypt-core API'
  s.extensions << 'ext/krypt/core/extconf.rb'
  s.files = %w(LICENSE) + Dir.glob('{bin,ext,lib,spec,test}/**/*')
  s.test_files = Dir.glob('test/**/test_*.rb')
  s.require_path = "lib"
  s.license = 'MIT'
end
