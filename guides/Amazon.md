# AWS KMS

Add this line to your application’s Gemfile:

```ruby
gem 'aws-sdk-kms'
gem 'kms_encrypted'
```

Add columns for the encrypted data and the encrypted KMS data keys

```ruby
add_column :users, :encrypted_email, :text
add_column :users, :encrypted_email_iv, :text
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

[AWS CloudTrail](https://aws.amazon.com/cloudtrail/) logs all decryption calls. However, to know what data is being decrypted, you’ll need to add context.

Add a `kms_encryption_context` method to your model.

```ruby
class User < ApplicationRecord
  def kms_encryption_context
    # some hash
  end
end
```

The context is used as part of the encryption and decryption process, so it must be a value that doesn’t change. Otherwise, you won’t be able to decrypt. Read more about [encryption context here](https://docs.aws.amazon.com/kms/latest/developerguide/encryption-context.html).

The primary key is a good choice, but auto-generated ids aren’t available until a record is created, and we need to encrypt before this. One solution is to preload the primary key. Here’s what it looks like with Postgres:

```ruby
class User < ApplicationRecord
  def kms_encryption_context
    self.id ||= self.class.connection.execute("select nextval('#{self.class.sequence_name}')").first["nextval"]
    {"Record" => "#{model_name}/#{id}"}
  end
end
```

Another solution is to first save the record without the encrypted data, then update it.

Confirm it worked in the [CloudTrail console](https://console.aws.amazon.com/cloudtrail/home#/events?EventName=Decrypt). Note that it can take 20 minutes for events to show up. Use “View Event” to see the encryption context. You can also use the AWS CLI.

```sh
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=Decrypt
```

If you haven’t already, enable CloudTrail storage to S3. [Amazon Athena](https://aws.amazon.com/athena/) is great for querying CloudTrail logs. Create a table (thanks to [this post](http://www.1strategy.com/blog/2017/07/25/auditing-aws-activity-with-cloudtrail-and-athena/) for the table structure) with:

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
    userIdentity.userName,
    requestParameters
FROM
    cloudtrail_logs
WHERE
    eventName = 'Decrypt'
    AND resources[1].arn = 'arn:aws:kms:...'
ORDER BY 1
```

There will also be `GenerateDataKey` events.

### Ensuring Context

You can require everything to have context by editing the key policy.

```json
{
    "Effect": "Allow",
    "Principal": {
        "AWS": "arn:aws:iam::..."
    },
    "Action": [
        "kms:Encrypt",
        "kms:GenerateDataKey"
    ],
    "Resource": "*",
    "Condition": {
        "Null": {
            "kms:EncryptionContextKeys": false
        }
    }
}
```

## Alerting

We recommend setting up alerts on suspicious behavior. To get near real-time alerts (20-30 second delay), use [CloudWatch Events](https://console.aws.amazon.com/cloudwatch/home#rules:).

Create a rule to match “Events by Service”. Choose “Key Management Service (KMS)” as the service name and “AWS API Call via CloudTrail” as the event type. For operations, select “Specific Operations” and enter “Decrypt”.

Since a target is required, create an SNS topic with no subscriptions to use as the target. You can also use this to post events to an external source if desired.

Give the rule a name like “Decryptions”. Once it’s created, open it and click “Show metrics for the rule”. Check “Invocations”. On the “Graphed Metrics” tab, change the statistic to “Sum” and the period to “1 minute”. Finally, click the bell icon to create an alarm.

## Key Rotation

KMS supports [automatic key rotation](https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html). No action is required in this case.

To manually rotate keys, replace the old KMS key id with the new key id in your model. Your app does not need the old key id to perform rotation (however, the key must still be enabled in your AWS account).

```sh
KMS_KEY_ID=arn:aws:kms:...
```

and run

```ruby
User.find_each do |user|
  user.rotate_kms_key!
end
```

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

To do this, add more columns

```ruby
add_column :users, :encrypted_phone, :text
add_column :users, :encrypted_phone_iv, :text
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

## File Uploads

While outside the scope of this gem, you can also use KMS for sensitive file uploads. Check out [this guide](https://ankane.org/aws-client-side-encryption) to learn more.
