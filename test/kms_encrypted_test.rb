require_relative "test_helper"

class KmsEncryptedTest < Minitest::Test
  def setup
    User.delete_all
    create_user
  end

  def test_create
    user = create_user
    assert_equal "test@example.org", user.email
    assert_equal "555-555-5555", user.phone
  end

  def test_read
    user = User.last
    assert_equal "test@example.org", user.email
    assert_equal "555-555-5555", user.phone
  end

  # used for manual testing to confirm no decryption
  def test_update
    user = User.last
    user.encrypted_kms_key = nil
    user.encrypted_email = nil
    user.update!(email: "test@example.org")
  end

  # TODO remove cached key when reloaded
  # use for manual testing to confirm refetch decryption key
  def test_reload
    puts "first"
    user = User.last
    user.phone
    user.reload
    user.phone
  end

  def test_rotate
    user = User.last
    fields = user.attributes
    user.rotate_kms_key!

    %w(encrypted_email encrypted_email_iv encrypted_kms_key).each do |attr|
      next if attr == "encrypted_kms_key" && test_key?
      assert user.send(attr) != fields[attr], "#{attr} expected to change"
    end

    user.reload
    assert_equal "test@example.org", user.email
  end

  def test_rotate_phone
    user = User.last
    fields = user.attributes
    user.rotate_kms_key_phone!

    %w(encrypted_phone encrypted_phone_iv encrypted_kms_key_phone).each do |attr|
      next if attr == "encrypted_kms_key_phone" && test_key?
      assert user.send(attr) != fields[attr], "#{attr} expected to change"
    end

    user.reload
    assert_equal "555-555-5555", user.phone
  end

  private

  def create_user
    # for now
    ActiveSupport::Deprecation.silence do
      User.create!(name: "Test", email: "test@example.org", phone: "555-555-5555")
    end
  end

  def test_key?
    ENV["KMS_KEY_ID"] == "insecure-test-key"
  end
end
