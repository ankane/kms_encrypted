module KmsEncrypted
  class Database
    attr_reader :record, :key_method, :options

    def initialize(record, key_method)
      @record = record
      @key_method = key_method
      @options = record.class.kms_keys[key_method.to_sym]
    end

    def name
      options[:name]
    end

    def plaintext
      record.instance_variable_get("@#{key_method}")
    end

    def ciphertext
      @ciphertext ||= record.send("encrypted_#{key_method}")
    end

    def current_version
      @current_version ||= begin
        version = options[:current_version]
        version = record.instance_exec(&version) if version.respond_to?(:call)
        version.to_i
      end
    end

    def versions
      @versions ||= begin
        versions = options[:versions] || {}
        versions[current_version] ||= options[:key_id] || ENV["KMS_KEY_ID"]
        versions
      end
    end

    def context
      @context ||= begin
        context_method = name ? "kms_encryption_context_#{name}" : "kms_encryption_context"
        if record.method(context_method).arity == 0
          record.send(context_method)
        else
          record.send(context_method, version: current_version)
        end
      end
    end

    def key_id
      @key_id ||= begin
        raise ArgumentError, "current_version must be an integer" unless current_version.is_a?(Integer)

        key_id = versions[current_version]
        raise ArgumentError, "Missing key id" unless key_id

        key_id
      end
    end

    def encrypt(plaintext = nil)
      plaintext ||= self.plaintext

      event = {
        key_id: key_id,
        context: context,
        data_key: true
      }

      encoded_ciphertext =
        ActiveSupport::Notifications.instrument("encrypt.kms_encrypted", event) do
          case key_provider(key_id)
          when :test
            "insecure-data-key-#{Base64.strict_encode64(plaintext)}"
          when :google
            encode64(KmsEncrypted::Clients::Google.new(key_id: key_id).encrypt(plaintext, context: context.to_json))
          when :vault
            KmsEncrypted::Clients::Vault.new(key_id: key_id).encrypt(plaintext, context: context.to_json)
          else
            encode64(KmsEncrypted::Clients::Aws.new(key_id: key_id).encrypt(plaintext, context: context))
          end
        end

      "kms:v#{current_version}:#{encoded_ciphertext}"
    end

    def decrypt
      # TODO better validation
      if ciphertext.start_with?("kms:")
        parts = ciphertext.split(":", 3)
        version = parts[1][1..-1].to_i
        ciphertext = parts[2].to_s
      else
        version = 1
      end

      key_id = versions[version]
      raise ArgumentError, "Missing key id" unless key_id

      event = {
        key_id: key_id,
        context: context,
        data_key: true
      }

      ActiveSupport::Notifications.instrument("decrypt.kms_encrypted", event) do
        if ciphertext.start_with?("$gc$")
          _, _, short_key_id, ciphertext = ciphertext.split("$", 4)
          ciphertext = Base64.decode64(ciphertext)

          # restore key, except for cryptoKeyVersion
          stored_key_id = Base64.decode64(short_key_id).split("/")[0..3]
          stored_key_id.insert(0, "projects")
          stored_key_id.insert(2, "locations")
          stored_key_id.insert(4, "keyRings")
          stored_key_id.insert(6, "cryptoKeys")
          key_id = stored_key_id.join("/")

          KmsEncrypted::Clients::Google.new(key_id: key_id).decrypt(ciphertext, context: context.to_json)
        else
          case key_provider(key_id)
          when :test
            Base64.decode64(ciphertext.remove("insecure-data-key-"))
          when :google
            ciphertext = Base64.decode64(ciphertext)
            KmsEncrypted::Clients::Google.new(key_id: key_id).decrypt(ciphertext, context: context.to_json)
          when :vault
            KmsEncrypted::Clients::Vault.new(key_id: key_id).decrypt(ciphertext, context: context.to_json)
          else
            ciphertext = Base64.decode64(ciphertext)
            KmsEncrypted::Clients::Aws.new(key_id: key_id).decrypt(ciphertext, context: context)
          end
        end
      end
    end

    def encode64(bytes)
      Base64.encode64(bytes).delete("\n=")
    end

    def key_provider(key_id)
      if key_id == "insecure-test-key"
        :test
      elsif key_id.start_with?("projects/")
        :google
      elsif key_id.start_with?("vault/")
        :vault
      else
        :aws
      end
    end
  end
end
