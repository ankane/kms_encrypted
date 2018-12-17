module KmsEncrypted
  module Clients
    class Base
      attr_reader :key_id

      def initialize(key_id: nil, legacy_context: false)
        @key_id = key_id
        @legacy_context = legacy_context
      end

      protected

      def decryption_failed!
        raise DecryptionError, "Decryption failed"
      end

      # keys must be ordered consistently
      # values are checked for validity
      # then converted to strings
      def generate_context(context)
        if @legacy_context
          context.to_json
        elsif context.is_a?(Hash)
          Hash[context.sort_by { |k| k.to_s }.map { |k, v| [context_key(k), context_value(v)] }].to_json
        else
          context
        end
      end

      def context_key(k)
        unless k.is_a?(String) || k.is_a?(Symbol)
          raise ArgumentError, "Context keys must be a string or symbol"
        end
        k.to_s
      end

      def context_value(v)
        unless v.is_a?(String) || v.is_a?(Integer)
          raise ArgumentError, "Context values must be a string or integer"
        end
        v.to_s
      end
    end
  end
end
