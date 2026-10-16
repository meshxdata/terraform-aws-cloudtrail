mock_provider "aws" {
  mock_data "aws_caller_identity" {
    defaults = {
      account_id = "123456789012"
    }
  }

  mock_data "aws_partition" {
    defaults = {
      partition = "aws"
    }
  }

  mock_data "aws_region" {
    defaults = {
      name = "eu-west-1"
    }
  }

  mock_data "aws_iam_policy_document" {
    defaults = {
      json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
    }
  }
}

variables {
  trail_name           = "test-trail"
  bucket_name          = "test-trail-logs-bucket"
  kms_key_arn          = "arn:aws:kms:eu-west-1:123456789012:key/11111111-2222-3333-4444-555555555555"
  admin_principal_arns = ["arn:aws:iam::123456789012:role/break-glass"]
}

run "secure_defaults" {
  command = plan

  assert {
    condition     = aws_cloudtrail.this.enable_log_file_validation == true
    error_message = "Log file validation must be on."
  }

  assert {
    condition     = aws_cloudtrail.this.is_multi_region_trail == true
    error_message = "The trail must be multi-region by default."
  }

  assert {
    condition     = aws_s3_bucket_public_access_block.trail.block_public_acls == true && aws_s3_bucket_public_access_block.trail.restrict_public_buckets == true
    error_message = "Public access must be blocked on the trail bucket."
  }

  assert {
    condition     = aws_cloudwatch_log_group.trail[0].retention_in_days == 365
    error_message = "CloudWatch Logs retention must default to 365 days."
  }

  assert {
    condition     = length(aws_cloudtrail.this.advanced_event_selector) == 0
    error_message = "No data event selectors should be created by default."
  }
}

run "kms_and_object_lock" {
  command = plan

  assert {
    condition     = tolist(aws_s3_bucket_server_side_encryption_configuration.trail.rule)[0].apply_server_side_encryption_by_default[0].sse_algorithm == "aws:kms"
    error_message = "The bucket must use aws:kms."
  }

  assert {
    condition     = aws_cloudtrail.this.kms_key_id == var.kms_key_arn
    error_message = "The trail must use the customer managed key."
  }

  assert {
    condition     = aws_s3_bucket.trail.object_lock_enabled == true
    error_message = "Object Lock must be enabled on the trail bucket."
  }

  assert {
    condition     = tolist(aws_s3_bucket_object_lock_configuration.trail.rule)[0].default_retention[0].mode == "COMPLIANCE"
    error_message = "Object Lock must default to COMPLIANCE mode."
  }
}

run "rejects_missing_admins" {
  command = plan

  variables {
    admin_principal_arns = []
  }

  expect_failures = [
    var.admin_principal_arns,
  ]
}

run "rejects_non_kms_key" {
  command = plan

  variables {
    kms_key_arn = "not-a-key"
  }

  expect_failures = [
    var.kms_key_arn,
  ]
}

run "rejects_unknown_object_lock_mode" {
  command = plan

  variables {
    object_lock_mode = "NONE"
  }

  expect_failures = [
    var.object_lock_mode,
  ]
}

run "s3_data_events" {
  command = plan

  variables {
    s3_data_event_buckets = ["app-uploads"]
  }

  assert {
    condition     = length(aws_cloudtrail.this.advanced_event_selector) == 2
    error_message = "Data events should add a management and an S3 data selector."
  }
}

run "cloudwatch_logs_disabled" {
  command = plan

  variables {
    enable_cloudwatch_logs = false
  }

  assert {
    condition     = length(aws_cloudwatch_log_group.trail) == 0 && length(aws_iam_role.cloudtrail_logs) == 0
    error_message = "Disabling CloudWatch Logs must remove the log group and delivery role."
  }
}

run "rejects_short_retention" {
  command = plan

  variables {
    retention_days = 90
  }

  expect_failures = [
    var.retention_days,
  ]
}

run "rejects_bad_trail_name" {
  command = plan

  variables {
    trail_name = "bad name!"
  }

  expect_failures = [
    var.trail_name,
  ]
}
