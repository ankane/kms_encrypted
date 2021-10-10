module KmsEncrypted
  module Clients
    class Google < Base
      attr_reader :last_key_version

      def encrypt(plaintext, context: nil)
        options = {
          plaintext: plaintext
        }
        options[:additional_authenticated_data] = generate_context(context) if context

        # ensure namespace gets loaded
        client = KmsEncrypted.google_client

        if defined?(::Google::Apis::CloudkmsV1::CloudKMSService) && KmsEncrypted.google_client.is_a?(::Google::Apis::CloudkmsV1::CloudKMSService)
          request = ::Google::Apis::CloudkmsV1::EncryptRequest.new(**options)
          response = client.encrypt_crypto_key(key_id, request)
          @last_key_version = response.name
          response.ciphertext
        else
          options[:name] = key_id
          response = client.encrypt(**options)
          @last_key_version = response.name
          response.ciphertext
        end
      end

      def decrypt(ciphertext, context: nil)
        options = {
          ciphertext: ciphertext
        }
        options[:additional_authenticated_data] = generate_context(context) if context

        # ensure namespace gets loaded
        client = KmsEncrypted.google_client

        if defined?(::Google::Apis::CloudkmsV1::CloudKMSService) && KmsEncrypted.google_client.is_a?(::Google::Apis::CloudkmsV1::CloudKMSService)
          request = ::Google::Apis::CloudkmsV1::DecryptRequest.new(**options)
          begin
            client.decrypt_crypto_key(key_id, request).plaintext
          rescue ::Google::Apis::ClientError => e
            decryption_failed! if e.message.include?("Decryption failed")
            raise e
          end
        else
          options[:name] = key_id
          begin
            client.decrypt(**options).plaintext
          rescue ::Google::Cloud::InvalidArgumentError => e
            decryption_failed! if e.message.include?("Decryption failed")
            raise e
          end
        end
      end
    end
  end
end
