module KmsEncrypted
  class LogSubscriber < ActiveSupport::LogSubscriber
    def decrypt(event)
      return unless logger.debug?

      data_key = event.payload[:data_key]
      name = data_key ? "Decrypt Data Key" : "Decrypt"
      name += " (#{event.duration.round(1)}ms)"
      context = event.payload[:context]
      context = context.inspect if context.is_a?(Hash)
      debug "  #{color(name, YELLOW, true)}  Context: #{context}"
    end

    def encrypt(event)
      return unless logger.debug?

      data_key = event.payload[:data_key]
      name = data_key ? "Encrypt Data Key" : "Encrypt"
      name += " (#{event.duration.round(1)}ms)"
      context = event.payload[:context]
      context = context.inspect if context.is_a?(Hash)
      debug "  #{color(name, YELLOW, true)}  Context: #{context}"
    end
  end
end
