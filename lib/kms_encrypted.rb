require "kms_encrypted/version"
require "active_support"
require "aws-sdk-kms"

module KmsEncrypted
  def self.kms
    @kms ||= Aws::KMS::Client.new
  end

  module Model
    def has_kms_key(key_id)
      raise ArgumentError, "Missing key id" unless key_id

      class_eval do
        class << self
          attr_accessor :kms_key_id
        end
        self.kms_key_id = key_id

        def kms_key
          unless @kms_key
            key_id = self.class.kms_key_id
            context = respond_to?(:kms_encryption_context) ? kms_encryption_context : {}
            default_encoding = "m"

            unless encrypted_kms_key
              resp = KmsEncrypted.kms.generate_data_key(
                key_id: key_id,
                encryption_context: context,
                key_spec: "AES_256"
              )
              @kms_key = resp.plaintext
              ciphertext = resp.ciphertext_blob
              self.encrypted_kms_key = [resp.ciphertext_blob].pack(default_encoding)
            end

            unless @kms_key
              ciphertext = encrypted_kms_key.unpack(default_encoding).first
              resp = KmsEncrypted.kms.decrypt(
                ciphertext_blob: ciphertext,
                encryption_context: context
              )
              @kms_key = resp.plaintext
            end
          end

          @kms_key
        end
      end
    end
  end
end

ActiveSupport.on_load(:active_record) do
  extend KmsEncrypted::Model
end
