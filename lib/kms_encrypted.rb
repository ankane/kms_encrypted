# dependencies
require "active_support"
require "base64"

# modules
require "kms_encrypted/log_subscriber"
require "kms_encrypted/model"
require "kms_encrypted/version"

module KmsEncrypted
  class << self
    attr_writer :aws_client
    attr_writer :google_client
    attr_writer :vault_client

    def aws_client
      @aws_client ||= Aws::KMS::Client.new(
        retry_limit: 2,
        http_open_timeout: 2,
        http_read_timeout: 2
      )
    end

    def google_client
      @google_client ||= begin
        require "google/apis/cloudkms_v1"
        client = ::Google::Apis::CloudkmsV1::CloudKMSService.new
        client.authorization = ::Google::Auth.get_application_default(
          "https://www.googleapis.com/auth/cloud-platform"
        )
        client
      end
    end

    def vault_client
      @vault_client ||= ::Vault
    end

    def context_hash(record, path:)
      context = Base64.encode64(record.kms_encryption_context.to_json)
      vault_client.logical.write("sys/audit-hash/#{path}", input: context).data[:hash]
    end
  end
end

ActiveSupport.on_load(:active_record) do
  extend KmsEncrypted::Model
end

KmsEncrypted::LogSubscriber.attach_to :kms_encrypted
