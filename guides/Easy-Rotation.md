# Easy Rotation

Easy rotation can be used to:

1. Move to a different KMS
2. Change keys within your current KMS
3. Change your encryption context

It can be done with no downtime.

## Keys

To rotate keys, update your model:

```ruby
class User < ApplicationRecord
  has_kms_key key_id: ENV["KMS_KEY_ID_V2"], version: 2
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

## Context

To rotate context, update your model:

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
