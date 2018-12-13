module KmsEncrypted
  class LogSubscriber < ActiveSupport::LogSubscriber
    def decrypt(event)
      return unless logger.debug?

      data_key = event.payload[:data_key]
      name = data_key ? "Decrypt Data Key" : "Decrypt"
      name += " (#{event.duration.round(1)}ms)"
      debug "  #{color(name, YELLOW, true)}  Context: #{event.payload[:context].inspect}"
    end

    def encrypt(event)
      return unless logger.debug?

      data_key = event.payload[:data_key]
      name = data_key ? "Encrypt Data Key" : "Decrypt"
      name += " (#{event.duration.round(1)}ms)"
      debug "  #{color(name, YELLOW, true)}  Context: #{event.payload[:context].inspect}"
    end
  end
end
