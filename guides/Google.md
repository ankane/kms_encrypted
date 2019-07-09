# Google Cloud KMS

Add this line to your application’s Gemfile:

```ruby
gem 'google-api-client'
gem 'kms_encrypted'
```

Add a column for the encrypted KMS data keys

```ruby
add_column :users, :encrypted_kms_key, :text
```

Create a [Google Cloud Platform](https://cloud.google.com/) account if you don’t have one. KMS works great whether or not you run your infrastructure on GCP.

Create a [KMS key ring and key](https://console.cloud.google.com/iam-admin/kms) and set it in your environment along with your GCP credentials ([dotenv](https://github.com/bkeepers/dotenv) is great for this)

```sh
KMS_KEY_ID=projects/.../locations/.../keyRings/.../cryptoKeys/...
```

And update your model

```ruby
class User < ApplicationRecord
  has_kms_key

  # Lockbox
  encrypts :email, key: :kms_key

  # attr_encrypted
  attr_encrypted :email, key: :kms_key
end
```

For each encrypted attribute, use the `kms_key` method for its key.

## Logging

The Google API client logs requests by default. Be sure to turn off the logger in production or it will leak the plaintext.

```ruby
Google::Apis.logger = Logger.new(nil)
```

## Auditing

Follow the [instructions here](https://cloud.google.com/kms/docs/logging) to set up data access logging. There is not currently a way to see what data is being decrypted, since the additional authenticated data is not logged. For this reason, we recommend another KMS provider.

## Alerting

We recommend setting up alerts on suspicious behavior.

## Key Rotation

To rotate master keys, use the Google Cloud Console or API.

New data will be encrypted with the new master key version. To encrypt existing data with new master key version, run:

```ruby
User.find_each do |user|
  user.rotate_kms_key!
end
```

Use [easy rotation](Easy-Rotation.md) if you want to switch keys.

## Testing

For testing, you can prevent network calls to KMS by setting:

```sh
KMS_KEY_ID=insecure-test-key
```

## Multiple Keys Per Record

You may want to protect different columns with different data keys (or even master keys).

To do this, add another column

```ruby
add_column :users, :encrypted_kms_key_phone, :text
```

And update your model

```ruby
class User < ApplicationRecord
  has_kms_key
  has_kms_key name: :phone, key_id: "..."

  # Lockbox
  encrypts :email, key: :kms_key
  encrypts :phone, key: :kms_key_phone

  # attr_encrypted
  attr_encrypted :email, key: :kms_key
  attr_encrypted :phone, key: :kms_key_phone
end
```

For context, use:

```ruby
class User < ApplicationRecord
  def kms_encryption_context_phone
    # some hash
  end
end
```

To rotate keys, use:

```ruby
user.rotate_kms_key_phone!
```
