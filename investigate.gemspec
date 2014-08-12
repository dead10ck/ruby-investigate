# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'investigate'

Gem::Specification.new do |spec|
  spec.name          = "investigate"
  spec.version       = Investigate::VERSION
  spec.authors       = ["skyler"]
  spec.email         = ["skyler@opendns.com"]
  spec.summary       = "Ruby API for the OpenDNS Security Graph"
  spec.description   = spec.summary
  spec.homepage      = 'https://github.com/dead10ck/ruby-investigate'
  spec.license       = "MIT"

  spec.files         = `git ls-files -z`.split("\x0")
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ["lib"]

  spec.add_runtime_dependency "rest-client", "~> 1.7"
end
