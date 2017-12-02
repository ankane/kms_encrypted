# dependencies
require "active_support"
require "aws-sdk-kms"

# modules
require "kms_encrypted/model"
require "kms_encrypted/version"

module KmsEncrypted
  class << self
    attr_writer :kms_client

    def kms_client
      @kms_client ||= Aws::KMS::Client.new(client_options)
    end
    alias_method :kms, :kms_client

    # deprecated, use kms_client instead
    attr_reader :client_options

    # deprecated, use kms_client instead
    def client_options=(value)
      @client_options = value
      @kms_client = nil
    end
  end

  # deprecated, use kms_client instead
  self.client_options = {
    retry_limit: 2,
    http_open_timeout: 2,
    http_read_timeout: 2
  }
end

ActiveSupport.on_load(:active_record) do
  extend KmsEncrypted::Model
end
