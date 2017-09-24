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
  end
end
