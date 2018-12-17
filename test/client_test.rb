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
end
