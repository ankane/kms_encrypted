module KmsEncrypted
  class Client
    delegate :encrypt, :decrypt, to: :client

    attr_reader :key_id

    def initialize(key_id: nil)
      @key_id = key_id || ENV["KMS_KEY_ID"]
    end

    private

    def provider
      if key_id == "insecure-test-key"
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

        klass.new(key_id: key_id)
      end
    end
  end
end
