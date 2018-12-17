module KmsEncrypted
  module Clients
    class Aws < Base
      def encrypt(plaintext, context: nil)
        options = {
          key_id: key_id,
          plaintext: plaintext
        }
        options[:encryption_context] = generate_context(context) if context

        KmsEncrypted.aws_client.encrypt(options).ciphertext_blob
      end

      def decrypt(ciphertext, context: nil)
        options = {
          ciphertext_blob: ciphertext
        }
        options[:encryption_context] = generate_context(context) if context

        begin
          KmsEncrypted.aws_client.decrypt(options).plaintext
        rescue ::Aws::KMS::Errors::InvalidCiphertextException
          decryption_failed!
        end
      end

      private

      # make integers strings for convenience
      def generate_context(context)
        raise ArgumentError, "Context must be a hash" unless context.is_a?(Hash)
        Hash[context.map { |k, v| [k, context_value(v)] }]
      end
    end
  end
end
