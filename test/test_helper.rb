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
  if ENV["KMS_KEY_ID"].start_with?("projects/")
    KmsEncrypted.google_client.client_options.log_http_requests = true
  end
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
  t.string :encrypted_street
  t.string :encrypted_street_iv

  # kms_encrypted
  t.string :encrypted_kms_key
  t.string :encrypted_kms_key_phone
  t.string :encrypted_kms_key_street

  t.timestamps null: false
end

$version = 1

class User < ActiveRecord::Base
  has_kms_key
  has_kms_key name: :phone, eager_encrypt: :try
  has_kms_key name: :street, version: -> { $version },
    previous_versions: {
      1 => {key_id: "insecure-test-key"}
    }

  attr_encrypted :email, key: :kms_key
  attr_encrypted :phone, key: :kms_key_phone
  attr_encrypted :street, key: :kms_key_street

  def kms_encryption_context
    {"Name" => name}
  end

  def kms_encryption_context_street(version:)
    {version: version}
  end
end
