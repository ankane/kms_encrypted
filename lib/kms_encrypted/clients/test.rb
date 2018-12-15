module KmsEncrypted
  module Clients
    class Test < Base
      PREFIX = Base64.decode64("insecure+test+key+A")

      def encrypt(plaintext, context: nil)
        # TODO check context
        PREFIX + plaintext
      end

      def decrypt(ciphertext, context: nil)
        ciphertext.sub(PREFIX, "")
      end
    end
  end
end
