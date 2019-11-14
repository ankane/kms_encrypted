## 1.1.0 (2019-07-09)

- Added support for Lockbox
- Dropped support for Rails 4.2

## 1.0.1 (2019-01-21)

- Added support for encryption and decryption outside models
- Added support for dynamic keys
- Fixed issue with inheritance

## 1.0.0 (2018-12-17)

- Added versioning
- Added `context_hash` method

Breaking changes

- There’s now a default encryption context with the model name and id
- ActiveSupport notifications were changed from `generate_data_key` and `decrypt_data_key` to `encrypt` and `decrypt`
- AWS KMS uses the `Encrypt` operation instead of `GenerateDataKey`

## 0.3.0 (2018-11-11)

- Added support for Vault
- Removed `KmsEncrypted.kms_client` and `KmsEncrypted.client_options` in favor of `KmsEncrypted.aws_client`
- Removed `KmsEncrypted::Google.kms_client` in favor of `KmsEncrypted.google_client`

## 0.2.0 (2018-02-23)

- Added support for Google KMS

## 0.1.4 (2017-12-03)

- Added `kms_keys` method to models
- Reset data keys when record is reloaded
- Added `kms_client`
- Added ActiveSupport notifications

## 0.1.3 (2017-12-01)

- Added test key
- Added `client_options`
- Allow private or protected `kms_encryption_context` method

## 0.1.2 (2017-09-25)

- Use `KMS_KEY_ID` env variable by default

## 0.1.1 (2017-09-23)

- Added key rotation
- Added support for multiple keys per record

## 0.1.0 (2017-09-23)

- First release
