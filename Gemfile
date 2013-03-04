source 'https://rubygems.org'

group :development do
  gem 'rake'
  gem 'rake-compiler'
end

group :test do
  gem 'rspec'
  gem 'krypt',                  :path => File.expand_path('../krypt', File.dirname(__FILE__))
  gem 'krypt-provider-openssl', :path => File.expand_path('../krypt-provider-openssl', File.dirname(__FILE__))
  gem 'binyo',                  :path => File.expand_path('../binyo', File.dirname(__FILE__))

end

gemspec
