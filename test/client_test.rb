require_relative "test_helper"

class ClientTest < Minitest::Test
  def test_encrypt
    client = KmsEncrypted::Client.new
    plaintext = "hello" * 100
    context = {test: 123}
    ciphertext = client.encrypt(plaintext, context: context)
    assert_equal plaintext, client.decrypt(ciphertext, context: context)
  end
end
