module KmsEncrypted
  class Client
    attr_reader :key_id

    def initialize(key_id: nil)
      @key_id = key_id
    end

    def generate_data_key(context:)
      plaintext_key = nil
      encrypted_key = nil
      default_encoding = "m"

      event = {
        key_id: key_id,
        context: context
      }
      ActiveSupport::Notifications.instrument("generate_data_key.kms_encrypted", event) do
        if key_id == "insecure-test-key"
          plaintext_key = "00000000000000000000000000000000"
          encrypted_key = encrypt(plaintext_key, context: context)
        elsif key_id.start_with?("projects/")
          plaintext_key = random_key
          encrypted_key = encrypt(plaintext_key, context: context)
        elsif key_id.start_with?("vault/")
          plaintext_key = random_key
          encrypted_key = encrypt(plaintext_key, context: context)
        else
          # generate data key from API
          resp = KmsEncrypted.aws_client.generate_data_key(
            key_id: key_id,
            encryption_context: context,
            key_spec: "AES_256"
          )
          plaintext_key = resp.plaintext
          encrypted_key = [resp.ciphertext_blob].pack(default_encoding)
        end
      end

      [plaintext_key, encrypted_key]
    end

    def encrypt(plaintext, context:)
      default_encoding = "m"

      if key_id == "insecure-test-key"
        "insecure-data-key-#{rand(1_000_000_000_000)}"
      elsif key_id.start_with?("projects/")
        # encrypt it
        # load client first to ensure namespace is loaded
        client = KmsEncrypted.google_client
        request = ::Google::Apis::CloudkmsV1::EncryptRequest.new(
          plaintext: plaintext,
          additional_authenticated_data: context.to_json
        )
        response = client.encrypt_crypto_key(key_id, request)
        key_version = response.name

        # shorten key to save space
        short_key_id = Base64.encode64(key_version.split("/").select.with_index { |_, i| i.odd? }.join("/"))

        # build encrypted key
        # we reference the key in the field for easy rotation
        encrypted_key = "$gc$#{short_key_id}$#{[response.ciphertext].pack(default_encoding)}"
      elsif key_id.start_with?("vault/")
        # encrypt it
        response = KmsEncrypted.vault_client.logical.write(
          "transit/encrypt/#{key_id.sub("vault/", "")}",
          plaintext: Base64.encode64(plaintext),
          context: Base64.encode64(context.to_json)
        )

        response.data[:ciphertext]
      else
        resp = KmsEncrypted.aws_client.encrypt(
          key_id: key_id,
          plaintext: plaintext,
          encryption_context: context
        )
        [resp.ciphertext_blob].pack(default_encoding)
      end
    end

    def random_key
      SecureRandom.random_bytes(32)
    end

    def decrypt(ciphertext, context:)
      default_encoding = "m"

      event = {
        key_id: key_id,
        context: context
      }

      ActiveSupport::Notifications.instrument("decrypt_data_key.kms_encrypted", event) do
        if ciphertext.start_with?("insecure-data-key-")
          "00000000000000000000000000000000".encode("BINARY")
        elsif ciphertext.start_with?("$gc$")
          _, _, short_key_id, ct = ciphertext.split("$", 4)

          # restore key, except for cryptoKeyVersion
          stored_key_id = Base64.decode64(short_key_id).split("/")[0..3]
          stored_key_id.insert(0, "projects")
          stored_key_id.insert(2, "locations")
          stored_key_id.insert(4, "keyRings")
          stored_key_id.insert(6, "cryptoKeys")
          stored_key_id = stored_key_id.join("/")

          # load client first to ensure namespace is loaded
          client = KmsEncrypted.google_client
          request = ::Google::Apis::CloudkmsV1::DecryptRequest.new(
            ciphertext: ct.unpack(default_encoding).first,
            additional_authenticated_data: context.to_json
          )
          client.decrypt_crypto_key(stored_key_id, request).plaintext
        elsif ciphertext.start_with?("vault:")
          response = KmsEncrypted.vault_client.logical.write(
            "transit/decrypt/#{key_id.sub("vault/", "")}",
            ciphertext: ciphertext,
            context: Base64.encode64(context.to_json)
          )

          Base64.decode64(response.data[:plaintext])
        else
          KmsEncrypted.aws_client.decrypt(
            ciphertext_blob: ciphertext.unpack(default_encoding).first,
            encryption_context: context
          ).plaintext
        end
      end
    end
  end
end
