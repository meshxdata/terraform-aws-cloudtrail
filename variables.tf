variable "trail_name" {
  type        = string
  description = "Name of the CloudTrail trail."

  validation {
    condition     = can(regex("^[a-zA-Z0-9._-]{3,128}$", var.trail_name))
    error_message = "trail_name must be 3-128 characters: letters, numbers, dots, underscores, hyphens."
  }
}

variable "bucket_name" {
  type        = string
  description = "Name of the S3 bucket that stores trail logs. Must be globally unique."
}

variable "retention_days" {
  type        = number
  description = "Days to keep trail logs. PCI DSS requires at least 365."
  default     = 400

  validation {
    condition     = var.retention_days >= 365 && var.retention_days <= 3653
    error_message = "retention_days must be between 365 and 3653 so the trail meets PCI DSS Requirement 10.5.1."
  }
}

variable "kms_key_arn" {
  type        = string
  description = "Customer managed KMS key that encrypts the bucket, the trail, and the CloudWatch Logs group. The key policy must allow CloudTrail and CloudWatch Logs to use it."

  validation {
    condition     = can(regex("^arn:[^:]+:kms:[^:]+:[0-9]{12}:key/.+$", var.kms_key_arn))
    error_message = "kms_key_arn must be a KMS key ARN."
  }
}

variable "admin_principal_arns" {
  type        = list(string)
  description = "IAM role or user ARNs allowed to change or delete the trail bucket's protections. Everyone else is denied those actions. Use a break-glass role, not a broad account principal."

  validation {
    condition     = length(var.admin_principal_arns) >= 1 && alltrue([for a in var.admin_principal_arns : can(regex("^arn:[^:]+:iam::[0-9]{12}:(role|user)/.+$", a))])
    error_message = "admin_principal_arns needs at least one IAM role or user ARN."
  }
}

variable "object_lock_mode" {
  type        = string
  description = "S3 Object Lock mode for log objects. COMPLIANCE cannot be shortened or removed by anyone, including the root user. GOVERNANCE can be bypassed by principals with s3:BypassGovernanceRetention."
  default     = "COMPLIANCE"

  validation {
    condition     = contains(["COMPLIANCE", "GOVERNANCE"], var.object_lock_mode)
    error_message = "object_lock_mode must be COMPLIANCE or GOVERNANCE."
  }
}

variable "enable_cloudwatch_logs" {
  type        = bool
  description = "Send trail events to CloudWatch Logs, so alarms and metric filters can run on them."
  default     = true
}

variable "cloudwatch_logs_retention_days" {
  type        = number
  description = "Retention in days for the CloudWatch Logs group. Must be a value CloudWatch Logs accepts."
  default     = 365

  validation {
    condition     = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653], var.cloudwatch_logs_retention_days)
    error_message = "cloudwatch_logs_retention_days must be a value CloudWatch Logs accepts, for example 90, 365, 400."
  }
}

variable "s3_data_event_buckets" {
  type        = list(string)
  description = "Bucket names whose object-level (data) events are logged. Empty logs management events only."
  default     = []
}

variable "multi_region" {
  type        = bool
  description = "Record events from all regions in one trail."
  default     = true
}

variable "logging_target_bucket" {
  type        = string
  description = "Bucket that receives server access logs for the trail bucket. Null disables access logging."
  default     = null
}

variable "logging_target_prefix" {
  type        = string
  description = "Prefix for server access log objects."
  default     = ""
}

variable "tags" {
  type        = map(string)
  description = "Tags applied to the bucket and the trail."
  default     = {}
}
