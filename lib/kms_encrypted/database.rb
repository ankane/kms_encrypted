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
      @version ||= begin
        version = options[:version]
        version = record.instance_exec(&version) if version.respond_to?(:call)
        version.to_i
      end
    end

    def key_version(version)
      versions = (options[:previous_versions] || {}).dup
      versions[current_version] ||= options.slice(:key_id)

      raise "Version not active: #{version}" unless versions[version]

      key_id = versions[version][:key_id]

      raise ArgumentError, "Missing key id" unless key_id

      key_id
    end

    def context(version)
      context_method = name ? "kms_encryption_context_#{name}" : "kms_encryption_context"
      if record.method(context_method).arity == 0
        record.send(context_method)
      else
        record.send(context_method, version: version)
      end
    end

    def encrypt(plaintext = nil)
      plaintext ||= self.plaintext

      key_id = key_version(current_version)
      context = context(current_version)

      event = {
        key_id: key_id,
        context: context,
        data_key: true
      }

      ciphertext =
        ActiveSupport::Notifications.instrument("encrypt.kms_encrypted", event) do
          KmsEncrypted::Client.new(key_id: key_id).encrypt(plaintext, context: context)
        end

      "v#{current_version}:#{encode64(ciphertext)}"
    end

    def decrypt
      ciphertext = self.ciphertext

      m = /\Av(\d+):/.match(ciphertext)
      if m
        version = m[1].to_i
        ciphertext = ciphertext.sub("v#{version}:", "")
      else
        version = 1
        context = {} if options[:upgrade_context]

        # legacy
        if ciphertext.start_with?("$gc$")
          _, _, short_key_id, ciphertext = ciphertext.split("$", 4)

          # restore key, except for cryptoKeyVersion
          stored_key_id = decode64(short_key_id).split("/")[0..3]
          stored_key_id.insert(0, "projects")
          stored_key_id.insert(2, "locations")
          stored_key_id.insert(4, "keyRings")
          stored_key_id.insert(6, "cryptoKeys")
          key_id = stored_key_id.join("/")
        end
      end

      key_id ||= key_version(version)
      context ||= context(version)
      ciphertext = decode64(ciphertext)

      event = {
        key_id: key_id,
        context: context,
        data_key: true
      }
      ActiveSupport::Notifications.instrument("decrypt.kms_encrypted", event) do
        KmsEncrypted::Client.new(key_id: key_id).decrypt(ciphertext, context: context)
      end
    end

    def encode64(bytes)
      Base64.encode64(bytes).delete("\n=")
    end

    def decode64(bytes)
      Base64.decode64(bytes)
    end
  end
end
