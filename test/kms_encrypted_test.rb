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

  def test_update_does_not_decrypt
    assert_operations encrypt: 1, decrypt: 0 do
      user = User.last
      user.encrypted_kms_key = nil
      user.encrypted_email = nil
      ActiveSupport::Deprecation.silence do
        user.update!(email: "test@example.org")
      end
    end
  end

  def test_reload_clears_data_key_cache
    assert_operations encrypt: 0, decrypt: 2 do
      user = User.last
      user.phone
      user.reload
      user.phone
    end
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

  def test_kms_keys
    assert User.kms_keys[:kms_key]
    assert User.kms_keys[:kms_key_phone]
  end

  private

  def assert_operations(expected)
    kms_client = KmsEncrypted.kms_client
    begin
      logger_io = StringIO.new
      KmsEncrypted.kms_client = Aws::KMS::Client.new(logger: ActiveSupport::Logger.new(logger_io))
      yield
      str = logger_io.string
      actual = {
        encrypt: str.scan(/generate_data_key/).length,
        decrypt: str.scan(/decrypt/).length
      }
      skip if test_key?
      assert_equal expected, actual
    ensure
      KmsEncrypted.kms_client = kms_client
    end
  end

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
