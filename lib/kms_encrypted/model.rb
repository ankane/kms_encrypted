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
        kms_keys[key_method.to_sym] = {key_id: key_id, name: name}

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

        if kms_keys.size == 1
          after_save :encrypt_kms_keys

          # fetch all keys together so only need to update database once
          def encrypt_kms_keys
            updates = {}
            self.class.kms_keys.each do |key_method, key|
              instance_var = "@#{key_method}"
              key_column = "encrypted_#{key_method}"
              plaintext_key = instance_variable_get(instance_var)

              if !send(key_column) && plaintext_key
                name = key[:name]
                context_method = name ? "kms_encryption_context_#{name}" : "kms_encryption_context"
                context = respond_to?(context_method, true) ? send(context_method) : {}
                updates[key_column] = KmsEncrypted::Database.encrypt(plaintext_key, key_id: key[:key_id], context: context)
              end
            end
            if updates.any?
              current_time = current_time_from_proper_timezone
              timestamp_attributes_for_update_in_model.each do |attr|
                updates[attr] = current_time
              end
              update_columns(updates)
            end
          end
        end

        define_method(key_method) do
          raise ArgumentError, "Missing key id" unless key_id

          instance_var = "@#{key_method}"

          unless instance_variable_get(instance_var)
            encrypted_key = send("encrypted_#{key_method}")
            plaintext_key =
              if encrypted_key
                context_method = name ? "kms_encryption_context_#{name}" : "kms_encryption_context"
                context = respond_to?(context_method, true) ? send(context_method) : {}
                KmsEncrypted::Database.decrypt_data_key(encrypted_key, key_id: key_id, context: context)
              else
                # TODO can encrypt here if preload option set
                # maybe also have option to preload
                # prefetch_key: true/false/:when_possible ()
                # prefetch_id: true/false (default false)
                SecureRandom.random_bytes(32)
              end
            instance_variable_set(instance_var, plaintext_key)
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
