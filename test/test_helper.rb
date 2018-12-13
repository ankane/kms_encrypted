require "bundler/setup"
require "active_record"
require "attr_encrypted"
Bundler.require(:default)
require "minitest/autorun"
require "minitest/pride"
require "aws-sdk-kms"
require "google/apis/cloudkms_v1"

# must come before vault
ENV["VAULT_ADDR"] ||= "http://127.0.0.1:8200"
require "vault"

ActiveRecord::Base.establish_connection adapter: "sqlite3", database: ":memory:"

ENV["KMS_KEY_ID"] ||= "insecure-test-key"

if ENV["VERBOSE"]
  logger = ActiveSupport::Logger.new(STDOUT)
  Aws.config[:logger] = logger
  ActiveRecord::Base.logger = logger
  ActiveSupport::LogSubscriber.logger = logger
  Google::Apis.logger = logger
end

$events = Hash.new(0)
ActiveSupport::Notifications.subscribe(/kms_encrypted/) do |name, _start, _finish, _id, _payload|
  $events[name.sub(".kms_encrypted", "").to_sym] += 1
end

ActiveRecord::Migration.create_table :users do |t|
  t.string :name
  t.string :encrypted_email
  t.string :encrypted_email_iv
  t.string :encrypted_phone
  t.string :encrypted_phone_iv

  # kms_encrypted
  t.string :encrypted_kms_key
  t.string :encrypted_kms_key_phone

  t.timestamps
end

class User < ActiveRecord::Base
  has_kms_key
  has_kms_key name: :phone, prefetch_key: :try

  attr_encrypted :email, key: :kms_key
  attr_encrypted :phone, key: :kms_key_phone

  def kms_encryption_context
    {"Name" => name}
  end
end
