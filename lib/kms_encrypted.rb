require "kms_encrypted/version"
require "active_support"
require "aws-sdk-kms"

module KmsEncrypted
  def self.kms
    @kms ||= Aws::KMS::Client.new
  end

  module Model
    def has_kms_key(legacy_key_id = nil, name: nil, key_id: nil)
      key_id ||= legacy_key_id || ENV["KMS_KEY_ID"]
      raise ArgumentError, "Missing key id" unless key_id

      key_method = name ? "kms_key_#{name}" : "kms_key"

      class_eval do
        define_method(key_method) do
          instance_var = "@#{key_method}"

          unless instance_variable_get(instance_var)
            key_column = "encrypted_#{key_method}"
            context_method = name ? "kms_encryption_context_#{name}" : "kms_encryption_context"
            context = respond_to?(context_method, true) ? send(context_method) : {}
            default_encoding = "m"

            unless send(key_column)
              resp = KmsEncrypted.kms.generate_data_key(
                key_id: key_id,
                encryption_context: context,
                key_spec: "AES_256"
              )
              ciphertext = resp.ciphertext_blob
              instance_variable_set(instance_var, resp.plaintext)
              self.send("#{key_column}=", [resp.ciphertext_blob].pack(default_encoding))
            end

            unless instance_variable_get(instance_var)
              ciphertext = send(key_column).unpack(default_encoding).first
              resp = KmsEncrypted.kms.decrypt(
                ciphertext_blob: ciphertext,
                encryption_context: context
              )
              instance_variable_set(instance_var, resp.plaintext)
            end
          end

          instance_variable_get(instance_var)
        end

        define_method("rotate_#{key_method}!") do
          # decrypt
          plaintext_attributes = {}
          self.class.encrypted_attributes.select { |_, v| v[:key] == key_method.to_sym }.keys.each do |key|
            plaintext_attributes[key] = send(key)
          end

          # reset key
          instance_variable_set("@#{key_method}", nil)
          send("encrypted_#{key_method}=", nil)

          # encrypt again
          plaintext_attributes.each do |attr, value|
            send("#{attr}=", value)
          end

          # update atomically
          save!
        end
      end
    end
  end
end

ActiveSupport.on_load(:active_record) do
  extend KmsEncrypted::Model
end
