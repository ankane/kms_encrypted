require_relative "lib/kms_encrypted/version"

Gem::Specification.new do |spec|
  spec.name          = "kms_encrypted"
  spec.version       = KmsEncrypted::VERSION
  spec.summary       = "Simple, secure key management for Lockbox and attr_encrypted"
  spec.homepage      = "https://github.com/ankane/kms_encrypted"
  spec.license       = "MIT"

  spec.author        = "Andrew Kane"
  spec.email         = "andrew@chartkick.com"

  spec.files         = Dir["*.{md,txt}", "{lib}/**/*"]
  spec.require_path  = "lib"

  spec.required_ruby_version = ">= 2.2"

  spec.add_dependency "activesupport", ">= 4.2"

  spec.add_development_dependency "bundler"
  spec.add_development_dependency "rake"
  spec.add_development_dependency "minitest"
  spec.add_development_dependency "sqlite3"
  spec.add_development_dependency "activerecord"
  spec.add_development_dependency "attr_encrypted"
  spec.add_development_dependency "lockbox", ">= 0.2"
  spec.add_development_dependency "aws-sdk-kms"
  spec.add_development_dependency "google-api-client"
  spec.add_development_dependency "vault"
end
