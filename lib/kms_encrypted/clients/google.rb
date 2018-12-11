module KmsEncrypted
  module Clients
    class Google < Base
      attr_reader :last_key_version

      def encrypt(plaintext, context: nil)
        client = KmsEncrypted.google_client
        options = {
          plaintext: plaintext
        }
        options[:additional_authenticated_data] = context if context

        request = ::Google::Apis::CloudkmsV1::EncryptRequest.new(options)
        response = client.encrypt_crypto_key(key_id, request)

        @last_key_version = response.name

        response.ciphertext
      end

      def decrypt(ciphertext, context: nil)
        client = KmsEncrypted.google_client
        options = {
          ciphertext: ciphertext
        }
        options[:additional_authenticated_data] = context if context

        request = ::Google::Apis::CloudkmsV1::DecryptRequest.new(options)
        client.decrypt_crypto_key(key_id, request).plaintext
      end
    end
  end
end
