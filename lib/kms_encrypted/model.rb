module KmsEncrypted
  module Model
    def has_kms_key(name: nil, key_id: nil, eager_encrypt: false, version: 1, previous_versions: nil, upgrade_context: false)
      key_id ||= KmsEncrypted.key_id

      key_method = name ? "kms_key_#{name}" : "kms_key"
      key_column = "encrypted_#{key_method}"
      context_method = name ? "kms_encryption_context_#{name}" : "kms_encryption_context"

      class_eval do
        @kms_keys ||= {}

        unless respond_to?(:kms_keys)
          def self.kms_keys
            parent_keys =
              if superclass.respond_to?(:kms_keys)
                superclass.kms_keys
              else
                {}
              end

            parent_keys.merge(@kms_keys || {})
          end
        end

        @kms_keys[key_method.to_sym] = {
          key_id: key_id,
          name: name,
          version: version,
          previous_versions: previous_versions,
          upgrade_context: upgrade_context
        }

        if @kms_keys.size == 1
          after_save :encrypt_kms_keys

          # fetch all keys together so only need to update database once
          def encrypt_kms_keys
            updates = {}
            self.class.kms_keys.each do |key_method, key|
              instance_var = "@#{key_method}"
              key_column = "encrypted_#{key_method}"
              plaintext_key = instance_variable_get(instance_var)

              if !send(key_column) && plaintext_key
                updates[key_column] = KmsEncrypted::Database.new(self, key_method).encrypt(plaintext_key)
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

          if method_defined?(:reload)
            m = Module.new do
              define_method(:reload) do |*args, &block|
                result = super(*args, &block)
                self.class.kms_keys.keys.each do |key_method|
                  instance_variable_set("@#{key_method}", nil)
                end
                result
              end
            end
            prepend m
          end
        end

        define_method(key_method) do
          instance_var = "@#{key_method}"

          unless instance_variable_get(instance_var)
            encrypted_key = send(key_column)
            plaintext_key =
              if encrypted_key
                KmsEncrypted::Database.new(self, key_method).decrypt(encrypted_key)
              else
                key = SecureRandom.random_bytes(32)

                if eager_encrypt == :fetch_id
                  raise ArgumentError, ":fetch_id only works with Postgres" unless self.class.connection.adapter_name =~ /postg/i
                  self.id ||= self.class.connection.execute("select nextval('#{self.class.sequence_name}')").first["nextval"]
                end

                if eager_encrypt == true || ([:try, :fetch_id].include?(eager_encrypt) && id)
                  encrypted_key = KmsEncrypted::Database.new(self, key_method).encrypt(key)
                  send("#{key_column}=", encrypted_key)
                end

                key
              end
            instance_variable_set(instance_var, plaintext_key)
          end

          instance_variable_get(instance_var)
        end

        define_method(context_method) do
          raise KmsEncrypted::Error, "id needed for encryption context" unless id

          {
            model_name: model_name.to_s,
            model_id: id
          }
        end

        # automatically detects attributes and files where the encryption key is:
        # 1. a symbol that matches kms key method exactly
        # does not detect attributes and files where the encryption key is:
        # 1. callable (warns)
        # 2. a symbol that internally calls kms key method
        # it could try to get the exact key and compare
        # (there's a very small chance this could have false positives)
        # but bias towards simplicity for now
        # TODO possibly raise error for callable keys in 2.0
        # with option to override/specify attributes
        define_method("rotate_#{key_method}!") do
          # decrypt
          plaintext_attributes = {}

          # attr_encrypted
          if self.class.respond_to?(:encrypted_attributes)
            self.class.encrypted_attributes.each do |key, v|
              if v[:key] == key_method.to_sym
                plaintext_attributes[key] = send(key)
              elsif v[:key].respond_to?(:call)
                warn "[kms_encrypted] Can't detect if encrypted attribute uses this key"
              end
            end
          end

          # lockbox attributes
          # only checks key, not previous versions
          if self.class.respond_to?(:lockbox_attributes)
            self.class.lockbox_attributes.each do |key, v|
              if v[:key] == key_method.to_sym
                plaintext_attributes[key] = send(key)
              elsif v[:key].respond_to?(:call)
                warn "[kms_encrypted] Can't detect if encrypted attribute uses this key"
              end
            end
          end

          # lockbox attachments
          # only checks key, not previous versions
          if self.class.respond_to?(:lockbox_attachments)
            self.class.lockbox_attachments.each do |key, v|
              if v[:key] == key_method.to_sym
                # can likely add support at some point, but may be complicated
                # ideally use rotate_encryption! from Lockbox
                # but needs access to both old and new keys
                # also need to update database atomically
                raise KmsEncrypted::Error, "Can't rotate key used for encrypted files"
              elsif v[:key].respond_to?(:call)
                warn "[kms_encrypted] Can't detect if encrypted attachment uses this key"
              end
            end
          end

          # CarrierWave uploaders
          if self.class.respond_to?(:uploaders)
            self.class.uploaders.each do |_, uploader|
              # for simplicity, only checks if key is callable
              if uploader.respond_to?(:lockbox_options) && uploader.lockbox_options[:key].respond_to?(:call)
                warn "[kms_encrypted] Can't detect if encrypted uploader uses this key"
              end
            end
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
