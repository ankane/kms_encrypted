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

  def test_update_eager_encrypt_false
    user = User.create!(name: "Test")
    assert_operations encrypt: 0 do
      user.email = "test@example.org"
    end
    assert_operations encrypt: 1 do
      user.save!
    end
    user = User.last
    assert_equal "test@example.org", user.email
  end

  def test_update_eager_encrypt_try
    user = User.create!(name: "Test")
    assert_operations encrypt: 1 do
      user.phone = "555-555-5555"
    end
    assert_operations encrypt: 0 do
      user.save!
    end
    user = User.last
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
      user.update!(email: "test@example.org")
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
      refute_equal user.send(attr), fields[attr]
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

  def test_inheritance
    assert_equal [:kms_key, :kms_key_phone, :kms_key_street], User.kms_keys.keys
    assert_equal [:kms_key, :kms_key_phone, :kms_key_street, :kms_key_child], ActiveUser.kms_keys.keys
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
    user1 = User.create!(street: "123 Main St")
    assert_start_with "v1:", user1.encrypted_kms_key_street

    user2 = User.create!(street: "123 Main St")
    assert_start_with "v1:", user2.encrypted_kms_key_street

    with_version(2) do
      user2 = User.last
      assert user2.street # can decrypt
      user2.rotate_kms_key_street!
      assert_start_with "v2:", user2.encrypted_kms_key_street
      user2.reload
      assert user2.street # can decrypt

      user1 = User.first
      user1.street # can decrypt
    end
  end

  def test_bad_version
    user = User.create!(street: "123 Main St")
    user.encrypted_kms_key_street = user.encrypted_kms_key_street.sub("v1:", "v3:")
    user.save!

    user = User.last
    error = assert_raises(KmsEncrypted::Error) do
      user.street
    end
    assert_equal "Version not active: 3", error.message
  end

  def test_lockbox
    user = create_user
    assert_equal "1970-01-01", user.date_of_birth
    user.reload
    assert_equal "1970-01-01", user.date_of_birth
  end

  def test_lockbox_rotate
    user = User.last
    fields = user.attributes
    user.rotate_kms_key!

    %w(date_of_birth_ciphertext encrypted_kms_key).each do |attr|
      refute_equal user.send(attr), fields[attr]
    end

    user.reload
    assert_equal "1970-01-01", user.date_of_birth
  end

  def test_lockbox_active_storage
    skip "Active Storage requires Active Record 5.2+" unless ActiveRecord::VERSION::STRING >= "5.2."

    user = ActiveStorageUser.create!
    error = assert_raises(KmsEncrypted::Error) do
      user.rotate_kms_key!
    end
    assert_equal "Can't rotate key used for encrypted files", error.message
  end

  def test_lockbox_active_storage_different_key
    skip "Active Storage requires Active Record 5.2+" unless ActiveRecord::VERSION::STRING >= "5.2."

    user = ActiveStorageAdmin.create!
    user.rotate_kms_key!
  end

  def test_lockbox_carrierwave
    user = CarrierWaveUser.create!
    _, stderr = capture_io do
      user.rotate_kms_key!
    end
    assert_match "Can't detect if encrypted uploader uses this key", stderr
  end

  def test_lockbox_carrierwave_different_key
    user = CarrierWaveAdmin.create!
    user.rotate_kms_key!
  end

  private

  def assert_operations(expected)
    $events.clear
    yield
    assert_equal expected.select { |k, v| v > 0 }, $events
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
    User.create!(name: "Test", email: "test@example.org", phone: "555-555-5555", date_of_birth: "1970-01-01")
  end
end
