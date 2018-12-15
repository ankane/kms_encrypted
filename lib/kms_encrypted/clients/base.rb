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

      def hash_to_context(v)
        v.to_json
      end
    end
  end
end
