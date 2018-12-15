module KmsEncrypted
  module Clients
    class Test < Base
      PREFIX = Base64.decode64("insecure+data+A")

      def encrypt(plaintext, context: nil)
        [PREFIX, Base64.strict_encode64(plaintext), Base64.strict_encode64(context.to_json)].join(":")
      end

      def decrypt(ciphertext, context: nil)
        prefix, plaintext, stored_context = ciphertext.split(":")

        decryption_failed! if context.to_json != Base64.decode64(stored_context)

        Base64.decode64(plaintext)
      end
    end
  end
end
