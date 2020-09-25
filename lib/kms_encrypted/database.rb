module KmsEncrypted
  class Database
    attr_reader :record, :key_method, :options

    def initialize(record, key_method)
      @record = record
      @key_method = key_method
      @options = record.class.kms_keys[key_method.to_sym]
    end

    def version
      @version ||= evaluate_option(:version).to_i
    end

    def key_id
      @key_id ||= evaluate_option(:key_id)
    end

    def previous_versions
      @previous_versions ||= evaluate_option(:previous_versions)
    end

    def context(version)
      name = options[:name]
      context_method = name ? "kms_encryption_context_#{name}" : "kms_encryption_context"
      if record.method(context_method).arity == 0
        record.send(context_method)
      else
        record.send(context_method, version: version)
      end
    end

    def encrypt(plaintext)
      context = context(version)

      KmsEncrypted::Box.new(
        key_id: key_id,
        version: version,
        previous_versions: previous_versions
      ).encrypt(plaintext, context: context)
    end

    def decrypt(ciphertext)
      # determine version for context
      m = /\Av(\d+):/.match(ciphertext)
      version = m ? m[1].to_i : 1
      context = (options[:upgrade_context] && !m) ? {} : context(version)

      KmsEncrypted::Box.new(
        key_id: key_id,
        version: version,
        previous_versions: previous_versions
      ).decrypt(ciphertext, context: context)
    end

    private

    def evaluate_option(key)
      opt = options[key]
      opt = record.instance_exec(&opt) if opt.respond_to?(:call)
      opt
    end
  end
end
