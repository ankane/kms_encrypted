require "bundler/setup"
require "active_record"
require "attr_encrypted"
Bundler.require(:default)
require "minitest/autorun"
require "minitest/pride"

ActiveRecord::Base.establish_connection adapter: "sqlite3", database: ":memory:"

ActiveRecord::Migration.create_table :users do |t|
  t.string :name
  t.string :encrypted_email
  t.string :encrypted_email_iv
  t.string :encrypted_kms_key
end

class User < ActiveRecord::Base
  has_kms_key ENV["KMS_KEY_ID"]

  attr_encrypted :email, key: :kms_key

  def kms_encryption_context
    {"Name" => name}
  end
end
