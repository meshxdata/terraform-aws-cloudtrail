output "trail_arn" {
  description = "ARN of the CloudTrail trail."
  value       = aws_cloudtrail.this.arn
}

output "bucket_id" {
  description = "Name of the S3 bucket that stores trail logs."
  value       = aws_s3_bucket.trail.id
}

output "bucket_arn" {
  description = "ARN of the S3 bucket that stores trail logs."
  value       = aws_s3_bucket.trail.arn
}

output "log_group_arn" {
  description = "ARN of the CloudWatch Logs group for trail events, or null when CloudWatch Logs is disabled."
  value       = try(aws_cloudwatch_log_group.trail[0].arn, null)
}
