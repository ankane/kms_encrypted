module KmsEncrypted
  module Clients
    class Aws < Base
      def encrypt(plaintext, context: nil)
        options = {
          key_id: key_id,
          plaintext: plaintext
        }
        options[:encryption_context] = context if context

        KmsEncrypted.aws_client.encrypt(options).ciphertext_blob
      end

      def decrypt(ciphertext, context: nil)
        options = {
          ciphertext_blob: ciphertext
        }
        options[:encryption_context] = context if context

        begin
          KmsEncrypted.aws_client.decrypt(options).plaintext
        rescue ::Aws::KMS::Errors::InvalidCiphertextException
          decryption_failed!
        end
      end

      def generate_data_key(context: nil)
        options = {
          key_id: key_id,
          key_spec: "AES_256"
        }
        options[:encryption_context] = context if context

        resp = KmsEncrypted.aws_client.generate_data_key(options)
        [resp.plaintext, resp.ciphertext_blob]
      end
    end
  end
end
