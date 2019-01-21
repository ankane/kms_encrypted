module KmsEncrypted
  class Box
    attr_reader :key_id, :version, :previous_versions

    def initialize(key_id: nil, version: nil, previous_versions: nil)
      @key_id = key_id || ENV["KMS_KEY_ID"]
      @version = version || 1
      @previous_versions = previous_versions || {}
    end

    def encrypt(plaintext, context: nil)
      key_id = version_key_id(version)
      ciphertext = KmsEncrypted::Client.new(key_id: key_id, data_key: true).encrypt(plaintext, context: context)
      "v#{version}:#{encode64(ciphertext)}"
    end

    def decrypt(ciphertext, context: nil)
      m = /\Av(\d+):/.match(ciphertext)
      if m
        version = m[1].to_i
        ciphertext = ciphertext.sub("v#{version}:", "")
      else
        version = 1
        legacy_context = true

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
        elsif ciphertext.start_with?("vault:")
          ciphertext = Base64.encode64(ciphertext)
        end
      end

      key_id ||= version_key_id(version)
      ciphertext = decode64(ciphertext)

      KmsEncrypted::Client.new(
        key_id: key_id,
        data_key: true,
        legacy_context: legacy_context
      ).decrypt(ciphertext, context: context)
    end

    private

    def version_key_id(version)
      key_id =
        if previous_versions[version]
          previous_versions[version][:key_id]
        elsif self.version == version
          self.key_id
        else
          raise KmsEncrypted::Error, "Version not active: #{version}"
        end

      raise ArgumentError, "Missing key id" unless key_id

      key_id
    end

    def encode64(bytes)
      Base64.strict_encode64(bytes)
    end

    def decode64(bytes)
      Base64.decode64(bytes)
    end
  end
end
