module KmsEncrypted
  module Database
    def self.generate_data_key(key_id:, context:)
      event = {
        key_id: key_id,
        context: context
      }
      ActiveSupport::Notifications.instrument("generate_data_key.kms_encrypted", event) do
        if key_id == "insecure-test-key"
          plaintext = "00000000000000000000000000000000".encode("BINARY")
          ciphertext = "insecure-data-key-#{rand(1_000_000_000_000)}"
          [plaintext, ciphertext]
        elsif key_id.start_with?("projects/")
          client = KmsEncrypted::Clients::Google.new(key_id: key_id)
          plaintext, ciphertext = client.generate_data_key(context: context.to_json)

          # shorten key to save space - super hacky :/
          short_key_id = client.last_key_version.split("/").select.with_index { |_, i| i.odd? }.join("/")

          # build encrypted key
          # we reference the key in the field for easy rotation
          [plaintext, "$gc$#{Base64.encode64(short_key_id)}$#{Base64.encode64(ciphertext)}"]
        elsif key_id.start_with?("vault/")
          KmsEncrypted::Clients::Vault.new(key_id: key_id).generate_data_key(context: context.to_json)
        else
          plaintext, ciphertext = KmsEncrypted::Clients::Aws.new(key_id: key_id).generate_data_key(context: context)
          [plaintext, Base64.encode64(ciphertext)]
        end
      end
    end

    def self.decrypt_data_key(ciphertext, key_id:, context:)
      event = {
        key_id: key_id,
        context: context
      }
      ActiveSupport::Notifications.instrument("decrypt_data_key.kms_encrypted", event) do
        if ciphertext.start_with?("insecure-data-key-")
          "00000000000000000000000000000000".encode("BINARY")
        elsif ciphertext.start_with?("$gc$")
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
        elsif ciphertext.start_with?("vault:")
          KmsEncrypted::Clients::Vault.new(key_id: key_id).decrypt(ciphertext, context: context.to_json)
        else
          ciphertext = Base64.decode64(ciphertext)
          KmsEncrypted::Clients::Aws.new(key_id: key_id).decrypt(ciphertext, context: context)
        end
      end
    end
  end
end
