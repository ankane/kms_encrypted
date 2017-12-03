module KmsEncrypted
  module Model
    def has_kms_key(legacy_key_id = nil, name: nil, key_id: nil)
      key_id ||= legacy_key_id || ENV["KMS_KEY_ID"]

      key_method = name ? "kms_key_#{name}" : "kms_key"

      class_eval do
        class << self
          def kms_keys
            @kms_keys ||= {}
          end unless respond_to?(:kms_keys)
        end
        kms_keys[key_method.to_sym] = {key_id: key_id}

        # same pattern as attr_encrypted reload
        if method_defined?(:reload) && kms_keys.size == 1
          alias_method :reload_without_kms_encrypted, :reload
          def reload(*args, &block)
            result = reload_without_kms_encrypted(*args, &block)
            self.class.kms_keys.keys.each do |key_method|
              instance_variable_set("@#{key_method}", nil)
            end
            result
          end
        end

        define_method(key_method) do
          raise ArgumentError, "Missing key id" unless key_id

          instance_var = "@#{key_method}"

          unless instance_variable_get(instance_var)
            key_column = "encrypted_#{key_method}"
            context_method = name ? "kms_encryption_context_#{name}" : "kms_encryption_context"
            context = respond_to?(context_method, true) ? send(context_method) : {}
            default_encoding = "m"

            unless send(key_column)
              plaintext_key = nil
              encrypted_key = nil

              event = {
                key_id: key_id,
                context: context
              }
              ActiveSupport::Notifications.instrument("generate_data_key.kms_encrypted", event) do
                if key_id == "insecure-test-key"
                  encrypted_key = "insecure-data-key-#{rand(1_000_000_000_000)}"
                  plaintext_key = "00000000000000000000000000000000"
                else
                  resp = KmsEncrypted.kms_client.generate_data_key(
                    key_id: key_id,
                    encryption_context: context,
                    key_spec: "AES_256"
                  )
                  encrypted_key = [resp.ciphertext_blob].pack(default_encoding)
                  plaintext_key = resp.plaintext
                end
              end

              instance_variable_set(instance_var, plaintext_key)
              self.send("#{key_column}=", encrypted_key)
            end

            unless instance_variable_get(instance_var)
              encrypted_key = send(key_column)
              plaintext_key = nil

              event = {
                key_id: key_id,
                context: context
              }
              ActiveSupport::Notifications.instrument("decrypt_data_key.kms_encrypted", event) do
                if key_id == "insecure-test-key"
                  plaintext_key = "00000000000000000000000000000000"
                else
                  plaintext_key = KmsEncrypted.kms_client.decrypt(
                    ciphertext_blob: encrypted_key.unpack(default_encoding).first,
                    encryption_context: context
                  ).plaintext
                end
              end

              instance_variable_set(instance_var, plaintext_key)
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
