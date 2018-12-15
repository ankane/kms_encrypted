# AWS KMS

Add this line to your application’s Gemfile:

```ruby
gem 'aws-sdk-kms'
gem 'kms_encrypted'
```

Add a column for the encrypted KMS data keys

```ruby
add_column :users, :encrypted_kms_key, :text
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

And update your model

```ruby
class User < ApplicationRecord
  has_kms_key

  attr_encrypted :email, key: :kms_key
end
```

For each encrypted attribute, use the `kms_key` method for its key.

## Auditing

[AWS CloudTrail](https://aws.amazon.com/cloudtrail/) logs all decryption calls. You can view them in the [CloudTrail console](https://console.aws.amazon.com/cloudtrail/home#/events?EventName=Decrypt). Note that it can take 20 minutes for events to show up. You can also use the AWS CLI.

```sh
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=Decrypt
```

If you haven’t already, enable CloudTrail storage to S3 to ensure events are accessible after 90 days. Later, you can use Amazon Athena and this [table structure](http://www.1strategy.com/blog/2017/07/25/auditing-aws-activity-with-cloudtrail-and-athena/) to query them.

Encryption context is used to identify the data being decrypted. This is the model name and id by default. You can customize this with:

```ruby
class User < ApplicationRecord
  def kms_encryption_context
    # some hash
  end
end
```

The context is used as part of the encryption and decryption process, so it must be a value that doesn’t change. Otherwise, you won’t be able to decrypt. Read more about [encryption context here](https://docs.aws.amazon.com/kms/latest/developerguide/encryption-context.html).

Use [easy rotation](Easy-Rotation.md) if you need to change the encryption context.

## Alerting

Set up alerts for suspicious behavior. To get near real-time alerts (20-30 second delay), use CloudWatch Events.

First, create a new SNS topic with a name like "decryptions". We’ll use this shortly.

Next, open [CloudWatch Events](https://console.aws.amazon.com/cloudwatch/home#rules:) and create a rule to match “Events by Service”. Choose “Key Management Service (KMS)” as the service name and “AWS API Call via CloudTrail” as the event type. For operations, select “Specific Operations” and enter “Decrypt”.

Select the SNS topic created earlier as the target and save the rule.

To set up an alarm, go to CloudWatch -> Metrics -> Events -> By Rule Name. Find the rule and check “Invocations”. On the “Graphed Metrics” tab, change the statistic to “Sum” and the period to “1 minute”. Finally, click the bell icon to create an alarm for high number of decryptions.

While the alarm we created isn’t super sophisticated, this set up provides a great foundation for alerting as your organization grows.

You can use the SNS topic or another target to send events to a log provider or SIEM, where can you do more advanced anomaly detection.

## Key Rotation

KMS supports [automatic key rotation](https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html).

When this happens, new data will be encrypted with the new master key. To encrypt existing data with new master key, run:

```ruby
User.find_each do |user|
  user.rotate_kms_key!
end
```

Use [easy rotation](Easy-Rotation.md) if you want to manually switch keys.

## IAM Permissions

A great feature of KMS is the ability to grant encryption and decryption permission separately.

To encrypt the data, use a policy with:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "EncryptData",
            "Effect": "Allow",
            "Action": "kms:GenerateDataKey",
            "Resource": "arn:aws:kms:..."
        }
    ]
}
```

If a system can only encrypt, you must clear out existing data and data keys before updates.

```ruby
user.encrypted_email = nil
user.encrypted_kms_key = nil
# before user.save or user.update
```

To decrypt the data, use a policy with:

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

Be extremely selective of systems you allow to decrypt.

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

## File Uploads

While outside the scope of this gem, you can also use KMS for sensitive file uploads. Check out [this guide](https://ankane.org/aws-client-side-encryption) to learn more.
