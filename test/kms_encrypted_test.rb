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
    assert_operations encrypt: 1 do
      user = User.last
      user.encrypted_kms_key = nil
      user.encrypted_email = nil
      ActiveSupport::Deprecation.silence do
        user.update!(email: "test@example.org")
      end
    end
  end

  def test_reload_clears_data_key_cache
    assert_operations decrypt: 2 do
      user = User.last
      user.email
      user.reload
      user.email
    end
  end

  def test_rotate
    user = User.last
    fields = user.attributes
    user.rotate_kms_key!

    %w(encrypted_email encrypted_email_iv encrypted_kms_key).each do |attr|
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
      assert user.send(attr) != fields[attr], "#{attr} expected to change"
    end

    user.reload
    assert_equal "555-555-5555", user.phone
  end

  def test_kms_keys
    assert User.kms_keys[:kms_key]
    assert User.kms_keys[:kms_key_phone]
  end

  def test_context_hash
    skip unless ENV["KMS_KEY_ID"].start_with?("vault/")

    context = User.last.kms_encryption_context
    context_hash = KmsEncrypted.context_hash(context, path: "file")
    assert context_hash.start_with?("hmac-sha256:")
  end

  def test_bad_context
    user = User.last
    user.name = "updated"
    user.save!
    assert_raises(KmsEncrypted::DecryptionError) do
      user.email
    end
  end

  def test_updated_at
    user = User.last
    refute_equal user.updated_at, user.created_at
  end

  def test_eager_encrypt_try
    user = User.create!
    assert_operations encrypt: 1 do
      user.phone = "test@example.org"
    end
  end

  def test_versions
    user = User.create!(street: "123 Main St")
    assert_start_with "v1:", user.encrypted_kms_key_street

    with_version(2) do
      user = User.last
      assert user.street # can decrypt
      user.rotate_kms_key_street!
      assert_start_with "v2:", user.encrypted_kms_key_street
    end
  end

  def test_bad_version
    user = User.create!(street: "123 Main St")
    user.encrypted_kms_key_street = user.encrypted_kms_key_street.sub("v1:", "v3:")
    user.save!

    user = User.last
    assert_raises "bad" do
      user.street
    end
  end

  private

  def assert_operations(expected)
    $events.clear
    yield
    assert_equal expected, $events
  end

  def assert_start_with(start, str)
    assert str.start_with?(start), "Expected to start with #{start}"
  end

  def with_version(version)
    previous_version = $version
    begin
      $version = version
      yield
    ensure
      $version = previous_version
    end
  end

  def create_user
    # for now
    ActiveSupport::Deprecation.silence do
      User.create!(name: "Test", email: "test@example.org", phone: "555-555-5555")
    end
  end
end
