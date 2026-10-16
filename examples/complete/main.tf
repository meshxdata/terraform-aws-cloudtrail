module "cloudtrail" {
  source = "../../"

  trail_name     = "org-audit"
  bucket_name    = "example-org-audit-trail-logs"
  retention_days = 400
  multi_region   = true

  kms_key_arn          = "arn:aws:kms:eu-west-1:123456789012:key/REPLACE-ME"
  admin_principal_arns = ["arn:aws:iam::123456789012:role/break-glass"]

  tags = {
    Environment = "prod"
  }
}
