require_relative "test_helper"

class ClientTest < Minitest::Test
  def test_encrypt
    skip if ENV["KMS_KEY_ID"] == "insecure-test-key"

    client = KmsEncrypted::Client.new
    plaintext = "hello"
    ciphertext = client.encrypt(plaintext)
    assert_equal plaintext, client.decrypt(ciphertext)
  end
end
