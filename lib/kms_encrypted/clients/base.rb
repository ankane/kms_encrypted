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

      # keys must be ordered consistently
      def hash_to_context(h)
        Hash[h.sort_by { |k| k.to_s }.map { |k, v| [k.to_s, hash_value(v)] }].to_json
      end

      def hash_value(v)
        unless v.is_a?(String) || v.is_a?(Integer)
          raise ArgumentError, "Context values must be a string or integer"
        end
        v
      end
    end
  end
end
