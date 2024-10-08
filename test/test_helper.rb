require "bundler/setup"
require "carrierwave"
require "active_record"
require "carrierwave/orm/activerecord"
Bundler.require(:default)
require "minitest/autorun"
require "minitest/pride"

# must come before vault
ENV["VAULT_ADDR"] ||= "http://127.0.0.1:8200"
require "vault"

if ENV["ADAPTER"] == "postgresql"
  ActiveRecord::Base.establish_connection adapter: "postgresql", database: "kms_encrypted_test"
else
  ActiveRecord::Base.establish_connection adapter: "sqlite3", database: ":memory:"
end

KmsEncrypted.key_id ||= "insecure-test-key"

logger = ActiveSupport::Logger.new(ENV["VERBOSE"] ? STDOUT : nil)
Aws.config[:logger] = logger
ActiveRecord::Base.logger = logger
ActiveSupport::LogSubscriber.logger = logger
Google::Apis.logger = logger if defined?(Google::Apis)

if ENV["VERBOSE"] && KmsEncrypted.key_id.start_with?("projects/")
  KmsEncrypted.google_client.client_options.log_http_requests = true
end
ActiveRecord::Migration.verbose = ENV["VERBOSE"]

$events = Hash.new(0)
ActiveSupport::Notifications.subscribe(/kms_encrypted/) do |name, _start, _finish, _id, _payload|
  $events[name.sub(".kms_encrypted", "").to_sym] += 1
end

ActiveRecord::Schema.define do
  create_table :users, force: true do |t|
    t.string :name

    # attr_encrypted
    t.text :encrypted_email
    t.text :encrypted_email_iv
    t.text :encrypted_phone
    t.text :encrypted_phone_iv
    t.text :encrypted_street
    t.text :encrypted_street_iv

    # lockbox
    t.text :date_of_birth_ciphertext
    t.text :city_ciphertext

    # kms_encrypted
    t.text :encrypted_kms_key
    t.text :encrypted_kms_key_phone
    t.text :encrypted_kms_key_street
    t.text :encrypted_kms_key_city

    t.timestamps null: false
  end

  create_table :active_storage_users, force: true do |t|
    t.text :encrypted_kms_key
  end

  create_table :active_storage_admins, force: true do |t|
    t.text :encrypted_kms_key
  end

  create_table :carrier_wave_users, force: true do |t|
    t.string :license
    t.text :encrypted_kms_key
  end

  create_table :carrier_wave_admins, force: true do |t|
    t.string :document
    t.text :encrypted_kms_key
  end
end

$version = 1

class User < ActiveRecord::Base
  has_kms_key
  has_kms_key name: :phone, eager_encrypt: :try, key_id: -> { KmsEncrypted.key_id }
  has_kms_key name: :street, version: -> { $version },
    previous_versions: {
      1 => {key_id: "insecure-test-key"}
    }
  has_kms_key name: :city, eager_encrypt: :fetch_id

  attr_encrypted :email, key: :kms_key
  attr_encrypted :phone, key: :kms_key_phone
  attr_encrypted :street, key: :kms_key_street

  has_encrypted :date_of_birth, key: :kms_key
  has_encrypted :city, key: :kms_key_city

  def kms_encryption_context
    {"Name" => name}
  end

  def kms_encryption_context_street(version:)
    {version: version}
  end
end

# ensure has_kms_key does not cause model schema to load
raise "has_kms_key loading model schema early" if User.send(:schema_loaded?)

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
