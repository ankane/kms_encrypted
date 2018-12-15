# KMS Encrypted

Simple, secure key management for [attr_encrypted](https://github.com/attr-encrypted/attr_encrypted)

With KMS Encrypted:

- Master encryption keys are not on application servers
- There’s an immutable audit log of all activity
- Decryption can be disabled if an attack is detected
- Encrypt and decrypt permissions can be granted separately
- It’s easy to rotate keys

Supports [AWS KMS](https://aws.amazon.com/kms/), [Google Cloud KMS](https://cloud.google.com/kms/), and [Vault](https://www.vaultproject.io/)

[![Build Status](https://travis-ci.org/ankane/kms_encrypted.svg?branch=master)](https://travis-ci.org/ankane/kms_encrypted)

## How It Works

This approach uses a key management service (KMS) to manage encryption keys and attr_encrypted to do the encryption.

To encrypt an attribute, we first generate a data key and encrypt it with the KMS. This is known as [envelope encryption](https://cloud.google.com/kms/docs/envelope-encryption). We pass the unencrypted version to attr_encrypted and store the encrypted version in the `encrypted_kms_key` column. For each record, we generate a different data key.

To decrypt an attribute, we first decrypt the data key with the KMS. Once we have the decrypted key, we pass it to attr_encrypted to decrypt the data. We can easily track decryptions since we have a different data key for each record.

## Getting Started

Follow the instructions for your key management service:

- [AWS KMS](guides/Amazon.md)
- [Google Cloud KMS](guides/Google.md)
- [Vault](guides/Vault.md)

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
