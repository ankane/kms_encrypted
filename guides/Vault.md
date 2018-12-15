# Vault

Add this line to your application’s Gemfile:

```ruby
gem 'vault'
gem 'kms_encrypted'
```

Add a column for the encrypted KMS data keys

```ruby
add_column :users, :encrypted_kms_key, :text
```

Enable the [transit](https://www.vaultproject.io/docs/secrets/transit/index.html) secrets engine

```sh
vault secrets enable transit
```

And create a key

```sh
vault write -f transit/keys/my-key
```

Set it in your environment along with your Vault credentials ([dotenv](https://github.com/bkeepers/dotenv) is great for this)

```sh
KMS_KEY_ID=vault/my-key
VAULT_ADDR=http://127.0.0.1:8200
VAULT_TOKEN=secret
```

And update your model

```ruby
class User < ApplicationRecord
  has_kms_key

  attr_encrypted :email, key: :kms_key
end
```

For each encrypted attribute, use the `kms_key` method for its key.

## Auditing

Follow the [instructions here](https://www.vaultproject.io/docs/audit/) to set up data access logging.

Context is used to identify the data being decrypted. This is the model name and id by default. You can customize this with:

```ruby
class User < ApplicationRecord
  def kms_encryption_context
    # some hash
  end
end
```

The context is used as part of the encryption and decryption process, so it must be a value that doesn’t change. Otherwise, you won’t be able to decrypt. Use [Advanced Rotation](Advanced-Rotation.md) if you need to change the encryption context.

**Note:** You need to set `derived` to true when creating the key for Vault to verify this value. If this is not done, the context cannot be trusted.

```sh
vault write transit/keys/my-key derived=true
```

Context will show up hashed in the audit logs. To get the hash for a record, use:

```ruby
KmsEncrypted.context_hash(record.kms_encryption_context, path: "file")
```

The `path` option should point to your audit device. Common paths are `file`, `syslog`, and `socket`.

## Alerting

We recommend setting up alerts on suspicious behavior.

## Key Rotation

To manually rotate keys, use:

```sh
vault write -f transit/keys/my-key/rotate
```

and run

```ruby
User.find_each do |user|
  user.rotate_kms_key!
end
```

Use [Advanced Rotation](Advanced-Rotation.md) if you want to switch keys.

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
