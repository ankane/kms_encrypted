module KmsEncrypted
  module Clients
    class Base
      attr_reader :key_id

      def initialize(key_id: nil)
        @key_id = key_id
      end

      def decryption_failed!
        raise DecryptionError, "Decryption failed"
      end
    end
  end
end
