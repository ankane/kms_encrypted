require "test_helper"

class KmsEncryptedTest < Minitest::Test
  def test_works
    # create
    user = User.create!(name: "Test", email: "test@example.org", phone: "555-555-5555")
    assert_equal "test@example.org", user.email
    assert_equal "555-555-5555", user.phone

    # read
    user = User.last
    assert_equal "test@example.org", user.email
    assert_equal "555-555-5555", user.phone

    fields = user.attributes
    user.rotate_kms_key!

    %w(encrypted_email encrypted_email_iv encrypted_kms_key).each do |attr|
      assert user.send(attr) != fields[attr], "#{attr} expected to change"
    end

    user = User.last
    assert_equal "test@example.org", user.email
    assert_equal "555-555-5555", user.phone
  end
end
