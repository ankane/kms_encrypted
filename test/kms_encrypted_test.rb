require "test_helper"

class KmsEncryptedTest < Minitest::Test
  def test_works
    # create
    user = User.create!(name: "Test", email: "test@example.org")
    assert_equal "test@example.org", user.email

    # read
    user = User.last
    assert_equal "test@example.org", user.email
  end
end
