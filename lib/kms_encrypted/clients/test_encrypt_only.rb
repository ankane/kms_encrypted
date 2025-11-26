module KmsEncrypted
  module Clients
    class TestEncryptOnly < Test
      def decrypt(*)
        decryption_failed!
      end
    end
  end
end
