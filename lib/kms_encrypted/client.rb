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
        case provider
        when :test
          KmsEncrypted::Clients::Test.new(key_id: key_id)
        when :vault
          KmsEncrypted::Clients::Vault.new(key_id: key_id)
        when :google
          KmsEncrypted::Clients::Google.new(key_id: key_id)
        else
          KmsEncrypted::Clients::Aws.new(key_id: key_id)
        end
      end
    end
  end
end
