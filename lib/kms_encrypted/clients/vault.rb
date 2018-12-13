module KmsEncrypted
  module Clients
    class Vault < Base
      def encrypt(plaintext, context: nil)
        options = {
          plaintext: Base64.encode64(plaintext)
        }
        options[:context] = Base64.encode64(context) if context

        response = KmsEncrypted.vault_client.logical.write(
          "transit/encrypt/#{key_id.sub("vault/", "")}",
          options
        )

        response.data[:ciphertext]
      end

      def decrypt(ciphertext, context: nil)
        options = {
          ciphertext: ciphertext
        }
        options[:context] = Base64.encode64(context) if context

        response =
          begin
            KmsEncrypted.vault_client.logical.write(
              "transit/decrypt/#{key_id.sub("vault/", "")}",
              options
            )
          rescue ::Vault::HTTPClientError => e
            decryption_failed! if e.message.include?("unable to decrypt")
            raise e
          end

        Base64.decode64(response.data[:plaintext])
      end
    end
  end
end
