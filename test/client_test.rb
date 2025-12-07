require_relative "test_helper"

class ClientTest < Minitest::Test
  def test_encrypt
    client = KmsEncrypted::Client.new
    plaintext = "hello" * 100
    context = {test: 123}
    ciphertext = client.encrypt(plaintext, context: context)
    assert_equal plaintext, client.decrypt(ciphertext, context: context)
  end

  def test_context_order
    client = KmsEncrypted::Client.new
    plaintext = "hello" * 100
    context1 = {a: 1, b: 2}
    context2 = {b: 2, a: 1}
    ciphertext = client.encrypt(plaintext, context: context1)
    assert_equal plaintext, client.decrypt(ciphertext, context: context2)
  end

  def test_encrypt_only
    client = KmsEncrypted::Client.new(key_id: "insecure-test-key/encrypt")

    plaintext = "hello" * 100
    context = {test: 123}
    ciphertext = client.encrypt(plaintext, context: context)

    assert ciphertext.start_with?(Base64.decode64("insecure+data+A"))

    error = assert_raises(KmsEncrypted::DecryptionError) do
      client.decrypt(ciphertext, context: context)
    end
    assert_equal "Decryption failed", error.message

    client = KmsEncrypted::Client.new(key_id: "insecure-test-key")
    assert_equal plaintext, client.decrypt(ciphertext, context: context)
  end
end
