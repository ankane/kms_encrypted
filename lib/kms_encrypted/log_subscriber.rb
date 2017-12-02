module KmsEncrypted
  class LogSubscriber < ActiveSupport::LogSubscriber
    def decrypt_data_key(event)
      return unless logger.debug?

      name = "Decrypt Data Key (#{event.duration.round(1)}ms)"
      debug "  #{color(name, YELLOW, true)}  Context: #{event.payload[:context].inspect}"
    end

    def generate_data_key(event)
      return unless logger.debug?

      name = "Generate Data Key (#{event.duration.round(1)}ms)"
      debug "  #{color(name, YELLOW, true)}  Context: #{event.payload[:context].inspect}"
    end
  end
end
