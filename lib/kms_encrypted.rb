# dependencies
require "active_support"

begin
  # aws-sdk v3
  require "aws-sdk-kms"
rescue LoadError
  begin
    # aws-sdk v2
    require "aws-sdk"
  rescue LoadError
    # do nothing
  end
end

begin
  require "google/apis/cloudkms_v1"
rescue LoadError
  # do nothing
end

# modules
require "kms_encrypted/log_subscriber"
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

  module Google
    class << self
      attr_writer :kms_client

      def kms_client
        @kms_client ||= begin
          client = ::Google::Apis::CloudkmsV1::CloudKMSService.new
          client.authorization = ::Google::Auth.get_application_default(
            "https://www.googleapis.com/auth/cloud-platform"
          )
          client
        end
      end
    end
  end
end

ActiveSupport.on_load(:active_record) do
  extend KmsEncrypted::Model
end

KmsEncrypted::LogSubscriber.attach_to :kms_encrypted
