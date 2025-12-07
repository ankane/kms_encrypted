module KmsEncrypted
  class Client
    attr_reader :key_id, :data_key

    def initialize(key_id: nil, legacy_context: false, data_key: false, client: nil)
      @key_id = key_id || KmsEncrypted.key_id
      @legacy_context = legacy_context
      @data_key = data_key
      @service_client = client
    end

    def encrypt(plaintext, context: nil)
      event = {
        key_id: key_id,
        context: context,
        data_key: data_key
      }

      ActiveSupport::Notifications.instrument("encrypt.kms_encrypted", event) do
        client.encrypt(plaintext, context: context)
      end
    end

    def decrypt(ciphertext, context: nil)
      event = {
        key_id: key_id,
        context: context,
        data_key: data_key
      }

      ActiveSupport::Notifications.instrument("decrypt.kms_encrypted", event) do
        client.decrypt(ciphertext, context: context)
      end
    end

    private

    def provider
      if key_id == "insecure-test-key" || key_id == "insecure-test-key-encrypt-only"
        :test
      elsif key_id.start_with?("vault/")
        :vault
      elsif key_id.start_with?("projects/")
        :google
      else
        :aws
      end
    end

    def client
      @client ||= begin
        klass =
          case provider
          when :test
            KmsEncrypted::Clients::Test
          when :vault
            KmsEncrypted::Clients::Vault
          when :google
            KmsEncrypted::Clients::Google
          else
            KmsEncrypted::Clients::Aws
          end

        klass.new(key_id: key_id, legacy_context: @legacy_context, client: @service_client)
      end
    end
  end
end
