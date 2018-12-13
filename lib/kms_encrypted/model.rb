module KmsEncrypted
  module Model
    def has_kms_key(legacy_key_id = nil, name: nil, key_id: nil, prefetch_key: false)
      key_id ||= legacy_key_id || ENV["KMS_KEY_ID"]

      key_method = name ? "kms_key_#{name}" : "kms_key"
      key_column = "encrypted_#{key_method}"
      context_method = name ? "kms_encryption_context_#{name}" : "kms_encryption_context"

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
                updates[key_column] = KmsEncrypted::Database.encrypt_data_key(plaintext_key, key_id: key[:key_id], context: send(context_method))
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
            encrypted_key = send(key_column)
            plaintext_key =
              if encrypted_key
                KmsEncrypted::Database.decrypt_data_key(encrypted_key,
                  key_id: key_id,
                  context: send(context_method)
                )
              else
                key = SecureRandom.random_bytes(32)

                if prefetch_key == :try_with_id
                  raise ArgumentError, ":try_with_id only works with Postgres" unless self.class.connection.adapter_name =~ /postg/i
                  self.id ||= self.class.connection.execute("select nextval('#{self.class.sequence_name}')").first["nextval"]
                end

                if prefetch_key == true || ([:try, :try_with_id].include?(prefetch_key) && id)
                  encrypted_key =
                    KmsEncrypted::Database.encrypt_data_key(key,
                      key_id: key_id,
                      context: send(context_method)
                    )
                  send("#{key_column}=", encrypted_key)
                end
                key
              end
            instance_variable_set(instance_var, plaintext_key)
          end

          instance_variable_get(instance_var)
        end

        define_method(context_method) do
          raise "id needed for encryption context" unless id

          {
            model_name: model_name.to_s,
            model_id: id.to_s
          }
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
