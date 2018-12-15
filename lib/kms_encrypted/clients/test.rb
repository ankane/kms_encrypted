module KmsEncrypted
  module Clients
    class Test < Base
      PREFIX = Base64.decode64("insecure+data+A")

      def encrypt(plaintext, context: nil)
        parts = [PREFIX, Base64.strict_encode64(plaintext)]
        parts << generate_context(context) if context
        parts.join(":")
      end

      def decrypt(ciphertext, context: nil)
        prefix, plaintext, stored_context = ciphertext.split(":")

        context = generate_context(context) if context
        decryption_failed! if context != stored_context

        Base64.decode64(plaintext)
      end

      private

      # turn hash into json
      def generate_context(context)
        Base64.encode64(super)
      end
    end
  end
end
