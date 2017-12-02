# dependencies
require "active_support"
require "aws-sdk-kms"

# modules
require "kms_encrypted/model"
require "kms_encrypted/version"

module KmsEncrypted
  class << self
    attr_reader :client_options

    def client_options=(value)
      @client_options = value
      @kms = nil
    end

    def kms
      @kms ||= Aws::KMS::Client.new(client_options)
    end
  end
  self.client_options = {
    retry_limit: 2,
    http_open_timeout: 2,
    http_read_timeout: 2
  }
end

ActiveSupport.on_load(:active_record) do
  extend KmsEncrypted::Model
end
