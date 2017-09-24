# KMS Encrypted

[KMS](https://aws.amazon.com/kms/) + [attr_encrypted](https://github.com/attr-encrypted/attr_encrypted)

The attr_encrypted gem is great for encryption, but:

1. Leaves you to manage the security of your keys
2. Doesn’t provide a great audit trail to see how data has been accessed

KMS addresses both issues and it’s easy to use them together.

**Note:** This has not been battle-tested in a production environment, so use with caution

## How It Works

This approach uses KMS to manage encryption keys and attr_encrypted to do the encryption.

To encrypt an attribute, we first generate a [data key](http://docs.aws.amazon.com/kms/latest/developerguide/concepts.html) from our KMS master key. KMS sends both encrypted and unencrypted versions of the data key. We pass the unencrypted version to attr_encrypted and store the encrypted version in the `encrypted_kms_key` column. For each record, we generate a different data key.

To decrypt an attribute, we first decrypt the data key with KMS. Once we have the decrypted key, we pass it to attr_encrypted to decrypt the data. We can easily track decryptions since we have a different data key for each record.

## Getting Started

Add this line to your application’s Gemfile:

```ruby
gem 'kms_encrypted'
```

Add a column to store encrypted KMS data keys

```ruby
add_column :users, :encrypted_kms_key, :string
```

Create a [KMS master key](https://console.aws.amazon.com/iam/home#/encryptionKeys) and set it in your environment (we recommend [dotenv](https://github.com/bkeepers/dotenv))

```sh
KMS_KEY_ID=arn:aws:kms:...
```

And update your model

```ruby
class User < ApplicationRecord
  has_kms_key ENV["KMS_KEY_ID"]

  attr_encrypted :email, key: :kms_key
end
```

For each encrypted attribute, use the `kms_key` method for its key.

## Auditing

[AWS CloudTrail](https://aws.amazon.com/cloudtrail/) logs all decryption calls. However, to know what data is being decrypted, you’ll need to add context.

Add a `kms_encryption_context` method to your model.

```ruby
class User < ApplicationRecord
  def kms_encryption_context
    # some hash
  end
end
```

The context is used as part of the encryption and decryption process, so it must be a value that doesn’t change. Otherwise, you won’t be able to decrypt. Read more about [encryption context here](http://docs.aws.amazon.com/kms/latest/developerguide/encryption-context.html).

The primary key is a good choice, but auto-generated ids aren’t available until a record is created, and we need to encrypt before this. One solution is to preload the primary key. Here’s what it looks like with Postgres:

```ruby
class User < ApplicationRecord
  def kms_encryption_context
    self.id ||= self.class.connection.execute("select nextval('#{self.class.sequence_name}')").first["nextval"]
    {"Record" => "#{model_name}/#{id}"}
  end
end
```

We recommend [Amazon Athena](https://aws.amazon.com/athena/) for querying CloudTrail logs. Create a table (thanks to [this post](http://www.1strategy.com/blog/2017/07/25/auditing-aws-activity-with-cloudtrail-and-athena/) for the table structure) with:

```sql
CREATE EXTERNAL TABLE cloudtrail_logs (
    eventversion STRING,
    userIdentity STRUCT<
        type:STRING,
        principalid:STRING,
        arn:STRING,
        accountid:STRING,
        invokedby:STRING,
        accesskeyid:STRING,
        userName:String,
        sessioncontext:STRUCT<
            attributes:STRUCT<
                mfaauthenticated:STRING,
                creationdate:STRING>,
            sessionIssuer:STRUCT<
                type:STRING,
                principalId:STRING,
                arn:STRING,
                accountId:STRING,
                userName:STRING>>>,
    eventTime STRING,
    eventSource STRING,
    eventName STRING,
    awsRegion STRING,
    sourceIpAddress STRING,
    userAgent STRING,
    errorCode STRING,
    errorMessage STRING,
    requestId  STRING,
    eventId  STRING,
    resources ARRAY<STRUCT<
        ARN:STRING,
        accountId:STRING,
        type:STRING>>,
    eventType STRING,
    apiVersion  STRING,
    readOnly BOOLEAN,
    recipientAccountId STRING,
    sharedEventID STRING,
    vpcEndpointId STRING,
    requestParameters STRING,
    responseElements STRING,
    additionalEventData STRING,
    serviceEventDetails STRING
)
ROW FORMAT SERDE 'com.amazon.emr.hive.serde.CloudTrailSerde'
STORED  AS INPUTFORMAT 'com.amazon.emr.cloudtrail.CloudTrailInputFormat'
OUTPUTFORMAT 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat'
LOCATION  's3://my-cloudtrail-logs/'
```

Change the last line to point to your CloudTrail log bucket and query away

```sql
SELECT
    eventTime,
    eventName,
    userIdentity.userName,
    requestParameters
FROM
    cloudtrail_logs
WHERE
    eventName = 'Decrypt'
ORDER BY 1
```

## Key Rotation [master]

To manually rotate keys, add the new key to your model

```sh
KMS_KEY_ID=arn:aws:kms:...
```

and run

```sh
User.find_each do |user|
  user.rotate_kms_key!
end
```

## Multiple Keys Per Record [master]

Add more columns

```ruby
add_column :users, :encrypted_kms_key_phone, :string
```

And update your model

```ruby
class User < ApplicationRecord
  has_kms_key key_id: ENV["KMS_KEY_ID"]
  has_kms_key key_id: ENV["KMS_KEY_ID"], name: :phone

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

## History

View the [changelog](https://github.com/ankane/kms_encrypted/blob/master/CHANGELOG.md)

## Contributing

Everyone is encouraged to help improve this project. Here are a few ways you can help:

- [Report bugs](https://github.com/ankane/kms_encrypted/issues)
- Fix bugs and [submit pull requests](https://github.com/ankane/kms_encrypted/pulls)
- Write, clarify, or fix documentation
- Suggest or add new features
