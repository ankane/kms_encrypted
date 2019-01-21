require_relative "test_helper"

class BoxTest < Minitest::Test
  def test_encrypt
    client = KmsEncrypted::Box.new
    plaintext = "hello" * 100
    context = {test: 123}
    ciphertext = client.encrypt(plaintext, context: context)
    assert_equal plaintext, client.decrypt(ciphertext, context: context)
  end

  def test_context_order
    client = KmsEncrypted::Box.new
    plaintext = "hello" * 100
    context1 = {a: 1, b: 2}
    context2 = {b: 2, a: 1}
    ciphertext = client.encrypt(plaintext, context: context1)
    assert_equal plaintext, client.decrypt(ciphertext, context: context2)
  end

  def test_context_proc
    client = KmsEncrypted::Box.new
    plaintext = "hello" * 100
    context = ->(v) { {test: 123} }
    ciphertext = client.encrypt(plaintext, context: context)
    assert_equal plaintext, client.decrypt(ciphertext, context: context)
  end
end
