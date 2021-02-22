# KMS Encrypted

Simple, secure key management for [Lockbox](https://github.com/ankane/lockbox) and [attr_encrypted](https://github.com/attr-encrypted/attr_encrypted)

With KMS Encrypted:

- Master encryption keys are not on application servers
- Encrypt and decrypt permissions can be granted separately
- There’s an immutable audit log of all activity
- Decryption can be disabled if an attack is detected
- It’s easy to rotate keys

Supports [AWS KMS](https://aws.amazon.com/kms/), [Google Cloud KMS](https://cloud.google.com/kms/), and [Vault](https://www.vaultproject.io/)

Check out [this post](https://ankane.org/sensitive-data-rails) for more info on securing sensitive data with Rails

[![Build Status](https://github.com/ankane/kms_encrypted/workflows/build/badge.svg?branch=master)](https://github.com/ankane/kms_encrypted/actions)

## How It Works

This approach uses a key management service (KMS) to manage encryption keys and Lockbox / attr_encrypted to do the encryption.

To encrypt an attribute, we first generate a data key and encrypt it with the KMS. This is known as [envelope encryption](https://cloud.google.com/kms/docs/envelope-encryption). We pass the unencrypted version to the encryption library and store the encrypted version in the `encrypted_kms_key` column. For each record, we generate a different data key.

To decrypt an attribute, we first decrypt the data key with the KMS. Once we have the decrypted key, we pass it to the encryption library to decrypt the data. We can easily track decryptions since we have a different data key for each record.

## Installation

Add this line to your application’s Gemfile:

```ruby
gem 'kms_encrypted'
```

And follow the instructions for your key management service:

- [AWS KMS](#aws-kms)
- [Google Cloud KMS](#google-cloud-kms)
- [Vault](#vault)

### AWS KMS

Add this line to your application’s Gemfile:

```ruby
gem 'aws-sdk-kms'
```

Create an [Amazon Web Services](https://aws.amazon.com/) account if you don’t have one. KMS works great whether or not you run your infrastructure on AWS.

Create a [KMS master key](https://console.aws.amazon.com/iam/home#/encryptionKeys) and set it in your environment along with your AWS credentials ([dotenv](https://github.com/bkeepers/dotenv) is great for this)

```sh
KMS_KEY_ID=arn:aws:kms:...
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
```

You can also use the alias

```sh
KMS_KEY_ID=alias/my-alias
```

### Google Cloud KMS

Add this line to your application’s Gemfile:

```ruby
gem 'google-apis-cloudkms_v1'
```

Create a [Google Cloud Platform](https://cloud.google.com/) account if you don’t have one. KMS works great whether or not you run your infrastructure on GCP.

Create a [KMS key ring and key](https://console.cloud.google.com/iam-admin/kms) and set it in your environment along with your GCP credentials ([dotenv](https://github.com/bkeepers/dotenv) is great for this)

```sh
KMS_KEY_ID=projects/.../locations/.../keyRings/.../cryptoKeys/...
```

The Google API client logs requests by default. Be sure to turn off the logger in production or it will leak the plaintext.

```ruby
Google::Apis.logger = Logger.new(nil)
```

### Vault

Add this line to your application’s Gemfile:

```ruby
gem 'vault'
```

Enable the [transit](https://www.vaultproject.io/docs/secrets/transit/index.html) secrets engine

```sh
vault secrets enable transit
```

And create a key

```sh
vault write -f transit/keys/my-key derived=true
```

Set it in your environment along with your Vault credentials ([dotenv](https://github.com/bkeepers/dotenv) is great for this)

```sh
KMS_KEY_ID=vault/my-key
VAULT_ADDR=http://127.0.0.1:8200
VAULT_TOKEN=secret
```

## Getting Started

Create a migration to add a column for the encrypted KMS data keys

```ruby
add_column :users, :encrypted_kms_key, :text
```

And update your model

```ruby
class User < ApplicationRecord
  has_kms_key

  # Lockbox fields
  encrypts :email, key: :kms_key

  # Lockbox files
  encrypts_attached :license, key: :kms_key

  # attr_encrypted fields
  attr_encrypted :email, key: :kms_key
end
```

For each encrypted attribute, use the `kms_key` method for its key.

## Auditing & Alerting

### Context

Encryption context is used in auditing to identify the data being decrypted. This is the model name and id by default. You can customize this with:

```ruby
class User < ApplicationRecord
  def kms_encryption_context
    {
      model_name: model_name.to_s,
      model_id: id
    }
  end
end
```

The context is used as part of the encryption and decryption process, so it must be a value that doesn’t change. Otherwise, you won’t be able to decrypt. You can [rotate the context](#switching-context) without downtime if needed.

### Order of Events

Since the default context includes the id, the data key cannot be encrypted until the record has an id. For new records, the default flow is:

1. Start a database transaction
2. Insert the record, getting back the id
3. Call KMS to encrypt the data key, passing the id as part of the context
4. Update the `encrypted_kms_key` column
5. Commit the database transaction

With Postgres, you can avoid a network call inside a transaction with:

```ruby
class User < ApplicationRecord
  has_kms_key eager_encrypt: :fetch_id
end
```

This changes the flow to:

1. Prefetch the id with the Postgres `nextval` function
2. Call KMS to encrypt the data key, passing the id as part of the context
3. Insert the record with the id and encrypted data key

If you don’t need the id from the database for context, you can use:

```ruby
class User < ApplicationRecord
  has_kms_key eager_encrypt: true
end
```

### AWS KMS

[AWS CloudTrail](https://aws.amazon.com/cloudtrail/) logs all decryption calls. You can view them in the [CloudTrail console](https://console.aws.amazon.com/cloudtrail/home#/events?EventName=Decrypt). Note that it can take 20 minutes for events to show up. You can also use the AWS CLI.

```sh
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=Decrypt
```

If you haven’t already, enable CloudTrail storage to S3 to ensure events are accessible after 90 days. Later, you can use Amazon Athena and this [table structure](https://www.1strategy.com/blog/2017/07/25/auditing-aws-activity-with-cloudtrail-and-athena/) to query them.

Read more about [encryption context here](https://docs.aws.amazon.com/kms/latest/developerguide/encryption-context.html).

#### Alerting

Set up alerts for suspicious behavior. To get near real-time alerts (20-30 second delay), use CloudWatch Events.

First, create a new SNS topic with a name like "decryptions". We’ll use this shortly.

Next, open [CloudWatch Events](https://console.aws.amazon.com/cloudwatch/home#rules:) and create a rule to match “Events by Service”. Choose “Key Management Service (KMS)” as the service name and “AWS API Call via CloudTrail” as the event type. For operations, select “Specific Operations” and enter “Decrypt”.

Select the SNS topic created earlier as the target and save the rule.

To set up an alarm, go to [this page](https://console.aws.amazon.com/cloudwatch/home?#metricsV2:graph=%7E();namespace=AWS/Events;dimensions=RuleName) in CloudWatch Metrics. Find the rule and check “Invocations”. On the “Graphed Metrics” tab, change the statistic to “Sum” and the period to “1 minute”. Finally, click the bell icon to create an alarm for high number of decryptions.

While the alarm we created isn’t super sophisticated, this setup provides a great foundation for alerting as your organization grows.

You can use the SNS topic or another target to send events to a log provider or [SIEM](https://en.wikipedia.org/wiki/Security_information_and_event_management), where can you do more advanced anomaly detection.

You should also use other tools to detect breaches, like an [IDS](https://www.alienvault.com/blogs/security-essentials/open-source-intrusion-detection-tools-a-quick-overview). You can use [Amazon GuardDuty](https://aws.amazon.com/guardduty/) if you run infrastructure on AWS.

### Google Cloud KMS

Follow the [instructions here](https://cloud.google.com/kms/docs/logging) to set up data access logging. There is not currently a way to see what data is being decrypted, since the additional authenticated data is not logged. For this reason, we recommend another KMS provider.

### Vault

Follow the [instructions here](https://www.vaultproject.io/docs/audit/) to set up data access logging.

**Note:** Vault will only verify this value if `derived` was set to true when creating the key. If this is not done, the context cannot be trusted.

Context will show up hashed in the audit logs. To get the hash for a record, use:

```ruby
KmsEncrypted.context_hash(record.kms_encryption_context, path: "file")
```

The `path` option should point to your audit device. Common paths are `file`, `syslog`, and `socket`.

## Separate Permissions

A great feature of KMS is the ability to grant encryption and decryption permission separately.

Be extremely selective of servers you allow to decrypt.

For servers that can only encrypt, clear out the existing data and data key before assigning new values (otherwise, you’ll get a decryption error).

```ruby
# Lockbox
user.email_ciphertext = nil
user.encrypted_kms_key = nil

# attr_encrypted
user.encrypted_email = nil
user.encrypted_email_iv = nil
user.encrypted_kms_key = nil
```

### AWS KMS

To encrypt the data, use an IAM policy with:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "EncryptData",
            "Effect": "Allow",
            "Action": "kms:Encrypt",
            "Resource": "arn:aws:kms:..."
        }
    ]
}
```

To decrypt the data, use an IAM policy with:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "DecryptData",
            "Effect": "Allow",
            "Action": "kms:Decrypt",
            "Resource": "arn:aws:kms:..."
        }
    ]
}
```

### Google Cloud KMS

todo: document

### Vault

To encrypt the data, use a policy with:

```hcl
path "transit/encrypt/my-key"
{
  capabilities = ["create", "update"]
}
```

To decrypt the data, use a policy with:

```hcl
path "transit/decrypt/my-key"
{
  capabilities = ["create", "update"]
}
```

Apply a policy with:

```sh
vault policy write encrypt encrypt.hcl
```

And create a token with specific policies with:

```sh
vault token create -policy=encrypt -policy=decrypt -no-default-policy
```

## Testing

For testing, you can prevent network calls to KMS by setting:

```sh
KMS_KEY_ID=insecure-test-key
```

## Key Rotation

Key management services allow you to rotate the master key without any code changes.

AWS KMS supports [automatic key rotation](https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html).

For Google Cloud, use the Google Cloud Console or API.

For Vault, use:

```sh
vault write -f transit/keys/my-key/rotate
```

New data will be encrypted with the new master key version. To encrypt existing data with new master key version, run:

```ruby
User.find_each do |user|
  user.rotate_kms_key!
end
```

**Note:** This method does not rotate encrypted files, so avoid calling `rotate_kms_key!` on models with file uploads for now.

### Switching Keys

You can change keys within your current KMS or move to a different KMS without downtime. Update your model:

```ruby
class User < ApplicationRecord
  has_kms_key version: 2, key_id: ENV["KMS_KEY_ID_V2"],
    previous_versions: {
      1 => {key_id: ENV["KMS_KEY_ID"]}
    }
end
```

New data will be encrypted with the new key. To update existing data, use:

```ruby
User.where("encrypted_kms_key NOT LIKE 'v2:%'").find_each do |user|
  user.rotate_kms_key!
end
```

Once all data is updated, you can remove the `previous_versions` option.

### Switching Context

You can change your encryption context without downtime. Update your model:

```ruby
class User < ApplicationRecord
  has_kms_key version: 2,
    previous_versions: {
      1 => {key_id: ENV["KMS_KEY_ID"]}
    }

  def kms_encryption_context(version:)
    if version == 1
      # previous context method
    else
      # new context method
    end
  end
end
```

New data will be encrypted with the new context. To update existing data, use:

```ruby
User.where("encrypted_kms_key NOT LIKE 'v2:%'").find_each do |user|
  user.rotate_kms_key!
end
```

Once all data is updated, you can remove the `previous_versions` option.

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

To rotate keys, use:

```ruby
user.rotate_kms_key_phone!
```

For custom context, use:

```ruby
class User < ApplicationRecord
  def kms_encryption_context_phone
    # some hash
  end
end
```

## Outside Models

To encrypt and decrypt outside of models, create a box:

```ruby
kms = KmsEncrypted::Box.new
```

You can pass `key_id`, `version`, and `previous_versions` if needed.

Encrypt

```ruby
kms.encrypt(message, context: {model_name: "User", model_id: 123})
```

Decrypt

```ruby
kms.decrypt(ciphertext, context: {model_name: "User", model_id: 123})
```

## Related Projects

To securely search encrypted data, check out [Blind Index](https://github.com/ankane/blind_index).

## Upgrading

### 1.0

KMS Encrypted 1.0 brings a number of improvements. Here are a few breaking changes to be aware of:

- There’s now a default encryption context with the model name and id
- ActiveSupport notifications were changed from `generate_data_key` and `decrypt_data_key` to `encrypt` and `decrypt`
- AWS KMS uses the `Encrypt` operation instead of `GenerateDataKey`

If you didn’t previously use encryption context, add the `upgrade_context` option to your models:

```ruby
class User < ApplicationRecord
  has_kms_key upgrade_context: true
end
```

Then run:

```ruby
User.where("encrypted_kms_key NOT LIKE 'v1:%'").find_each do |user|
  user.rotate_kms_key!
end
```

And remove the `upgrade_context` option.

## History

View the [changelog](CHANGELOG.md)

## Contributing

Everyone is encouraged to help improve this project. Here are a few ways you can help:

- [Report bugs](https://github.com/ankane/kms_encrypted/issues)
- Fix bugs and [submit pull requests](https://github.com/ankane/kms_encrypted/pulls)
- Write, clarify, or fix documentation
- Suggest or add new features

To get started with development and testing:

```sh
git clone https://github.com/ankane/kms_encrypted.git
cd kms_encrypted
bundle install
bundle exec rake test
```
