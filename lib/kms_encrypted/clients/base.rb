require "securerandom"

module KmsEncrypted
  module Clients
    class Base
      attr_reader :key_id

      def initialize(key_id: nil)
        @key_id = key_id
      end

      def generate_data_key(context: nil)
        key = SecureRandom.random_bytes(32)
        [key, encrypt(key, context: context)]
      end
    end
  end
end
