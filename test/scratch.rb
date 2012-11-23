# encoding: UTF-8

require 'krypt'
require_relative 'resources'
require 'stringio'
require 'pp'
require 'openssl'
require 'base64'
require 'benchmark'

p Krypt::Provider::PROVIDERS

d = Krypt::Digest.new("SHA1")
p d

result = d.hexdigest("test")
p result
