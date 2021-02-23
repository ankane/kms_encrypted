require "bundler/setup"
require "carrierwave"
require "active_record"
require "carrierwave/orm/activerecord"
Bundler.require(:default, :development)
require "minitest/autorun"
require "minitest/pride"
require "google/apis/cloudkms_v1"

# must come before vault
ENV["VAULT_ADDR"] ||= "http://127.0.0.1:8200"
require "vault"

ActiveRecord::Base.establish_connection adapter: "sqlite3", database: ":memory:"

KmsEncrypted.key_id ||= "insecure-test-key"

logger = ActiveSupport::Logger.new(ENV["VERBOSE"] ? STDOUT : nil)
Aws.config[:logger] = logger
ActiveRecord::Base.logger = logger
ActiveSupport::LogSubscriber.logger = logger
Google::Apis.logger = logger

if ENV["VERBOSE"] && KmsEncrypted.key_id.start_with?("projects/")
  KmsEncrypted.google_client.client_options.log_http_requests = true
end
ActiveRecord::Migration.verbose = ENV["VERBOSE"]

$events = Hash.new(0)
ActiveSupport::Notifications.subscribe(/kms_encrypted/) do |name, _start, _finish, _id, _payload|
  $events[name.sub(".kms_encrypted", "").to_sym] += 1
end

ActiveRecord::Migration.create_table :users do |t|
  t.string :name

  # attr_encrypted
  t.string :encrypted_email
  t.string :encrypted_email_iv
  t.string :encrypted_phone
  t.string :encrypted_phone_iv
  t.string :encrypted_street
  t.string :encrypted_street_iv

  # lockbox
  t.string :date_of_birth_ciphertext

  # kms_encrypted
  t.string :encrypted_kms_key
  t.string :encrypted_kms_key_phone
  t.string :encrypted_kms_key_street

  t.timestamps null: false
end

ActiveRecord::Migration.create_table :active_storage_users do |t|
  t.string :encrypted_kms_key
end

ActiveRecord::Migration.create_table :active_storage_admins do |t|
  t.string :encrypted_kms_key
end

ActiveRecord::Migration.create_table :carrier_wave_users do |t|
  t.string :license
  t.string :encrypted_kms_key
end

ActiveRecord::Migration.create_table :carrier_wave_admins do |t|
  t.string :document
  t.string :encrypted_kms_key
end

$version = 1

class User < ActiveRecord::Base
  has_kms_key
  has_kms_key name: :phone, eager_encrypt: :try, key_id: -> { KmsEncrypted.key_id }
  has_kms_key name: :street, version: -> { $version },
    previous_versions: {
      1 => {key_id: "insecure-test-key"}
    }

  attr_encrypted :email, key: :kms_key
  attr_encrypted :phone, key: :kms_key_phone
  attr_encrypted :street, key: :kms_key_street

  encrypts :date_of_birth, key: :kms_key

  def kms_encryption_context
    {"Name" => name}
  end

  def kms_encryption_context_street(version:)
    {version: version}
  end
end

class ActiveUser < User
  has_kms_key name: :child
end

class ActiveStorageUser < ActiveRecord::Base
  has_kms_key
  encrypts_attached :license, key: :kms_key
end

class ActiveStorageAdmin < ActiveRecord::Base
  has_kms_key
  encrypts_attached :license
end

CarrierWave.configure do |config|
  config.storage = :file
  config.store_dir = "/tmp/store"
  config.cache_dir = "/tmp/cache"
end

class LicenseUploader < CarrierWave::Uploader::Base
  encrypt key: -> { model.kms_key }
end

class DocumentUploader < CarrierWave::Uploader::Base
  encrypt
end

class CarrierWaveUser < ActiveRecord::Base
  has_kms_key
  mount_uploader :license, LicenseUploader
end

class CarrierWaveAdmin < ActiveRecord::Base
  has_kms_key
  mount_uploader :document, DocumentUploader
end
