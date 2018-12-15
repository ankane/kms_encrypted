require_relative "test_helper"

class ClientTest < Minitest::Test
  def test_encrypt
    client = KmsEncrypted::Client.new
    plaintext = "hello" * 100
    ciphertext = client.encrypt(plaintext)
    assert_equal plaintext, client.decrypt(ciphertext)
  end
end
