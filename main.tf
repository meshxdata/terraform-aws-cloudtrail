data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

locals {
  trail_arn = "arn:${data.aws_partition.current.partition}:cloudtrail:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:trail/${var.trail_name}"
}

resource "aws_s3_bucket" "trail" {
  #checkov:skip=CKV2_AWS_62:Event notifications depend on the consumer and are configured outside this module.
  #checkov:skip=CKV_AWS_144:Cross-region replication needs a destination bucket and IAM role, which are out of scope here.
  bucket              = var.bucket_name
  object_lock_enabled = true
  tags                = var.tags
}

resource "aws_s3_bucket_versioning" "trail" {
  bucket = aws_s3_bucket.trail.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "trail" {
  bucket                  = aws_s3_bucket.trail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_logging" "trail" {
  count         = var.logging_target_bucket == null ? 0 : 1
  bucket        = aws_s3_bucket.trail.id
  target_bucket = var.logging_target_bucket
  target_prefix = var.logging_target_prefix
}

# Object Lock makes logs write-once for the retention period, so they can't be deleted or overwritten
# before they expire, even by an administrator.
resource "aws_s3_bucket_object_lock_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id

  rule {
    default_retention {
      mode = var.object_lock_mode
      days = var.retention_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.trail]
}

# Retention for CloudTrail logs. PCI DSS Requirement 10.5.1 needs at least 365 days.
resource "aws_s3_bucket_lifecycle_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id

  rule {
    id     = "retention"
    status = "Enabled"

    filter {}

    expiration {
      days = var.retention_days
    }

    noncurrent_version_expiration {
      noncurrent_days = var.retention_days
    }
  }

  rule {
    id     = "abort-incomplete-multipart-uploads"
    status = "Enabled"

    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

resource "aws_s3_bucket_policy" "trail" {
  bucket = aws_s3_bucket.trail.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.trail.arn, "${aws_s3_bucket.trail.arn}/*"]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      },
      {
        Sid       = "DenyDestructiveActionsExceptAdmins"
        Effect    = "Deny"
        Principal = "*"
        Action = [
          "s3:BypassGovernanceRetention",
          "s3:DeleteBucket",
          "s3:DeleteBucketPolicy",
          "s3:DeleteObject",
          "s3:DeleteObjectVersion",
          "s3:PutBucketObjectLockConfiguration",
          "s3:PutBucketPublicAccessBlock",
          "s3:PutBucketVersioning",
          "s3:PutEncryptionConfiguration",
          "s3:PutBucketPolicy",
          "s3:PutLifecycleConfiguration",
        ]
        Resource = [aws_s3_bucket.trail.arn, "${aws_s3_bucket.trail.arn}/*"]
        Condition = {
          ArnNotLike = { "aws:PrincipalArn" = var.admin_principal_arns }
        }
      },
      {
        Sid       = "AWSCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.trail.arn
        Condition = {
          StringEquals = { "aws:SourceArn" = local.trail_arn }
        }
      },
      {
        Sid       = "AWSCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.trail.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl"  = "bucket-owner-full-control"
            "aws:SourceArn" = local.trail_arn
          }
        }
      }
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.trail]
}

resource "aws_cloudwatch_log_group" "trail" {
  count = var.enable_cloudwatch_logs ? 1 : 0

  name              = "/aws/cloudtrail/${var.trail_name}"
  retention_in_days = var.cloudwatch_logs_retention_days
  kms_key_id        = var.kms_key_arn
  tags              = var.tags
}

data "aws_iam_policy_document" "cloudtrail_assume" {
  count = var.enable_cloudwatch_logs ? 1 : 0

  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "cloudtrail_logs" {
  count = var.enable_cloudwatch_logs ? 1 : 0

  name               = "${var.trail_name}-cloudtrail-logs"
  assume_role_policy = data.aws_iam_policy_document.cloudtrail_assume[0].json
  tags               = var.tags
}

data "aws_iam_policy_document" "cloudtrail_logs" {
  count = var.enable_cloudwatch_logs ? 1 : 0

  statement {
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.trail[0].arn}:*"]
  }
}

resource "aws_iam_role_policy" "cloudtrail_logs" {
  count = var.enable_cloudwatch_logs ? 1 : 0

  name   = "cloudtrail-to-cloudwatch-logs"
  role   = aws_iam_role.cloudtrail_logs[0].id
  policy = data.aws_iam_policy_document.cloudtrail_logs[0].json
}

resource "aws_cloudtrail" "this" {
  #checkov:skip=CKV_AWS_252:SNS notifications for trail delivery are optional and configured outside this module.
  name           = var.trail_name
  s3_bucket_name = aws_s3_bucket.trail.id
  kms_key_id     = var.kms_key_arn

  is_multi_region_trail         = var.multi_region
  include_global_service_events = true
  enable_log_file_validation    = true

  cloud_watch_logs_group_arn = var.enable_cloudwatch_logs ? "${aws_cloudwatch_log_group.trail[0].arn}:*" : null
  cloud_watch_logs_role_arn  = var.enable_cloudwatch_logs ? aws_iam_role.cloudtrail_logs[0].arn : null

  dynamic "advanced_event_selector" {
    for_each = length(var.s3_data_event_buckets) > 0 ? [1] : []
    content {
      name = "Management events"
      field_selector {
        field  = "eventCategory"
        equals = ["Management"]
      }
    }
  }

  dynamic "advanced_event_selector" {
    for_each = length(var.s3_data_event_buckets) > 0 ? [1] : []
    content {
      name = "S3 object events for selected buckets"
      field_selector {
        field  = "eventCategory"
        equals = ["Data"]
      }
      field_selector {
        field  = "resources.type"
        equals = ["AWS::S3::Object"]
      }
      field_selector {
        field       = "resources.ARN"
        starts_with = [for b in var.s3_data_event_buckets : "arn:${data.aws_partition.current.partition}:s3:::${b}/"]
      }
    }
  }

  tags = var.tags

  depends_on = [aws_s3_bucket_policy.trail]
}
