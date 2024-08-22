# dependencies
require "active_support"
require "base64"
require "json"
require "securerandom"

# modules
require_relative "kms_encrypted/box"
require_relative "kms_encrypted/database"
require_relative "kms_encrypted/log_subscriber"
require_relative "kms_encrypted/model"
require_relative "kms_encrypted/version"

# clients
require_relative "kms_encrypted/client"
require_relative "kms_encrypted/clients/base"
require_relative "kms_encrypted/clients/aws"
require_relative "kms_encrypted/clients/google"
require_relative "kms_encrypted/clients/test"
require_relative "kms_encrypted/clients/vault"

module KmsEncrypted
  class Error < StandardError; end
  class DecryptionError < Error; end

  class << self
    attr_writer :aws_client
    attr_writer :google_client
    attr_writer :vault_client
    attr_writer :key_id

    def aws_client(force_reload: false)
      instance_variable_name = '@aws_client'

      instance_variable_set(instance_variable_name, nil) if force_reload
      return instance_variable_get(instance_variable_name) if instance_variable_get(instance_variable_name).present?

      instance_variable_set(
        instance_variable_name,
        begin
          override_credentials =
            if KmsEncrypted.config.aws_credentials_overridden?
              Aws::Credentials.new(KmsEncrypted.config.aws_access_key_id, KmsEncrypted.config.aws_secret_access_key)
            end

          params = {
            retry_limit: 1,
            http_open_timeout: 2,
            http_read_timeout: 2,
            credentials: override_credentials
          }.compact

          Aws::KMS::Client.new(params)
        end
      )
    end

    def google_client
      @google_client ||= begin
        begin
          require "google/apis/cloudkms_v1"

          client = ::Google::Apis::CloudkmsV1::CloudKMSService.new
          client.authorization = ::Google::Auth.get_application_default(
            "https://www.googleapis.com/auth/cloud-platform"
          )
          client.client_options.log_http_requests = false
          client.client_options.open_timeout_sec = 2
          client.client_options.read_timeout_sec = 2
          client
        rescue LoadError
          require "google/cloud/kms"

          Google::Cloud::Kms.key_management_service do |config|
            config.timeout = 2
          end
        end
      end
    end

    def vault_client
      @vault_client ||= ::Vault::Client.new
    end

    def key_id
      @key_id ||= ENV["KMS_KEY_ID"]
    end

    # hash is independent of key, but specific to audit device
    def context_hash(context, path:)
      context = Base64.encode64(context.to_json)
      vault_client.logical.write("sys/audit-hash/#{path}", input: context).data[:hash]
    end

    def config
      @config ||= Configuration.new
    end

    def configure
      yield(config)

      if config.aws_access_key_id.present? && config.aws_secret_access_key.nil?
        raise ArgumentError, "You must provide the `aws_secret_access_key` when `aws_access_key_id` is specified"
      end

      if config.aws_secret_access_key.present? && config.aws_access_key_id.nil?
        raise ArgumentError, "You must provide the `aws_access_key_id` when `aws_secret_access_key` is specified"
      end
    end
  end

  class Configuration
    attr_accessor :aws_access_key_id
    attr_accessor :aws_secret_access_key

    def aws_credentials_overridden?
      aws_access_key_id.present?
    end
  end
end

ActiveSupport.on_load(:active_record) do
  extend KmsEncrypted::Model
end

KmsEncrypted::LogSubscriber.attach_to :kms_encrypted
