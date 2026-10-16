# terraform-aws-cloudtrail

Creates a multi-region CloudTrail trail that writes to a hardened S3 bucket, with:

- Log file validation on
- A bucket that denies non-TLS requests and blocks all public access
- Object Lock in COMPLIANCE mode, so logs can't be deleted or overwritten before they expire, even by an administrator
- Deny statements for destructive bucket actions, except for the admin roles you list
- Versioning, and retention set by `retention_days` (400 days by default; PCI DSS needs at least 365)
- Required customer managed KMS encryption for the bucket, the trail, and the CloudWatch Logs group
- Optional server access logging for the bucket
- CloudWatch Logs delivery on by default, with its own IAM role, so alarms and metric filters can run on trail events (365-day retention)
- Optional S3 data events for the buckets you list
- Bucket policy statements scoped to this trail with `aws:SourceArn`, so the CloudTrail service can write only for this trail

## Usage

```hcl
module "cloudtrail" {
  source  = "meshxdata/cloudtrail/aws"
  version = "~> 1.0"

  trail_name     = "org-audit"
  bucket_name    = "my-org-audit-trail-logs"
  retention_days = 400

  kms_key_arn          = "arn:aws:kms:eu-west-1:123456789012:key/REPLACE-ME"
  admin_principal_arns = ["arn:aws:iam::123456789012:role/break-glass"]

  tags = {
    Environment = "prod"
  }
}
```

The key policy must allow the CloudTrail and CloudWatch Logs services to use the key.

**Object Lock is permanent.** In COMPLIANCE mode, objects can't be deleted until `retention_days` has passed, and the bucket can't be destroyed while objects are locked. Set `object_lock_mode = "GOVERNANCE"` if you need an escape hatch during testing.

See [examples/complete](examples/complete) for a full example.

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| trail_name | Name of the trail. | `string` | n/a | yes |
| bucket_name | Bucket that stores the trail logs. Must be globally unique. | `string` | n/a | yes |
| retention_days | Days to keep logs, from 365 to 3653. | `number` | `400` | no |
| kms_key_arn | Customer managed KMS key for the bucket, the trail, and the log group. | `string` | n/a | yes |
| admin_principal_arns | IAM roles or users allowed to change the bucket's protections. Everyone else is denied. | `list(string)` | n/a | yes |
| object_lock_mode | `COMPLIANCE` or `GOVERNANCE`. | `string` | `"COMPLIANCE"` | no |
| multi_region | Record events from all regions in one trail. | `bool` | `true` | no |
| logging_target_bucket | Bucket for server access logs. Null disables them. | `string` | `null` | no |
| logging_target_prefix | Prefix for server access log objects. | `string` | `""` | no |
| enable_cloudwatch_logs | Send trail events to CloudWatch Logs. | `bool` | `true` | no |
| cloudwatch_logs_retention_days | Retention for the CloudWatch Logs group. | `number` | `365` | no |
| s3_data_event_buckets | Buckets whose object-level events are logged. Empty logs management events only. | `list(string)` | `[]` | no |
| tags | Tags applied to the bucket and the trail. | `map(string)` | `{}` | no |

## Outputs

| Name | Description |
|------|-------------|
| trail_arn | ARN of the trail. |
| bucket_id | Name of the bucket that stores the logs. |
| bucket_arn | ARN of the bucket that stores the logs. |
| log_group_arn | ARN of the CloudWatch Logs group, or null when CloudWatch Logs is disabled. |

## Checks

CI runs `terraform fmt`, `terraform validate`, `terraform test`, Checkov, and Trivy on every push. The tests use a mocked AWS provider, so they need no credentials. Checkov checks that depend on surrounding infrastructure are skipped in `main.tf` with reasons: SNS delivery, event notifications, and replication.

Not covered by this module: MFA Delete (only the root user can enable it), and cross-account log aggregation.

## Requirements

| Name | Version |
|------|---------|
| terraform | >= 1.3 |
| aws | ~> 5.0 |
