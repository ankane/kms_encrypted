require_relative "lib/kms_encrypted/version"

Gem::Specification.new do |spec|
  spec.name          = "kms_encrypted"
  spec.version       = KmsEncrypted::VERSION
  spec.summary       = "Simple, secure key management for Lockbox and attr_encrypted"
  spec.homepage      = "https://github.com/ankane/kms_encrypted"
  spec.license       = "MIT"

  spec.author        = "Andrew Kane"
  spec.email         = "andrew@ankane.org"

  spec.files         = Dir["*.{md,txt}", "{lib}/**/*"]
  spec.require_path  = "lib"

  spec.required_ruby_version = ">= 2.6"

  spec.add_dependency "activesupport", ">= 5.2"
end
