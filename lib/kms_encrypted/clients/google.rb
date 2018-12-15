module KmsEncrypted
  module Clients
    class Google < Base
      attr_reader :last_key_version

      def encrypt(plaintext, context: nil)
        client = KmsEncrypted.google_client
        options = {
          plaintext: plaintext
        }
        options[:additional_authenticated_data] = generate_context(context) if context

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
        options[:additional_authenticated_data] = generate_context(context) if context

        request = ::Google::Apis::CloudkmsV1::DecryptRequest.new(options)
        begin
          client.decrypt_crypto_key(key_id, request).plaintext
        rescue ::Google::Apis::ClientError => e
          decryption_failed! if e.message.include?("Decryption failed")
          raise e
        end
      end

      private

      # turn hash into json
      def generate_context(context)
        context = hash_to_context(context) if context.is_a?(Hash)
        context
      end
    end
  end
end
