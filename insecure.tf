# =============================================================================
# insecure.tf — INTENTIONALLY MISCONFIGURED
#
# This file contains deliberate misconfigurations to demonstrate what
# Checkov (and KICS) will flag. DO NOT use these patterns in production.
#
# Run:  checkov -d . --quiet --compact --framework terraform
# =============================================================================

# -----------------------------------------------------------------------------
# [FINDING] CKV_AWS_20 — S3 bucket is publicly readable (ACL: public-read)
# Checkov check: ensure S3 bucket does not have public-read or public-read-write ACL
# -----------------------------------------------------------------------------
resource "aws_s3_bucket" "insecure_public_bucket" {
  bucket = "demo-insewwcure-public-bucket"
  # BAD: exposes all objects to the internet
  acl    = "public-read"

  tags = {
    Name = "InsecurePublicBucket"
  }
}

# [FINDING] CKV_AWS_19 — S3 bucket is not encrypted at rest
# No server-side encryption configuration bfffflock → Checkov will flag this.

# [FINDING] CKV_AWS_21 — S3 bucket versioning is not enabled
# No versioning block → Checkov will flag this.

# [FINDING] CKV_AWS_86 — S3 bucket does not have access logging enabled
# No logging block → Checkov will flag this.


# -----------------------------------------------------------------------------
# [FINDING] CKV_AWS_25 / CKV_AWS_24
# Security group allows unrestricted ingress on sensitive ports (0.0.0.0/0)
# -----------------------------------------------------------------------------
resource "aws_security_group" "insecure_sg" {
  name        = "insecure-sg"
  description = "Demo SG with overly permissive rules"
  vpc_id      = aws_vpc.main.id

  # BAD: SSH open to the entire internet
  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # [FINDING] CKV_AWS_25
  }

  # BAD: RDP open to the entire internet
  ingress {
    description = "RDP from anywhere"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # [FINDING] CKV_AWS_24
  }

  # BAD: all traffic allowed outbound (less critical but still flagged)
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "insecure-sg"
  }
}


# -----------------------------------------------------------------------------
# [FINDING] CKV_AWS_8 — EC2 instance does not have IMDSv2 enforced
# [FINDING] CKV_AWS_135 — EC2 instance not using encrypted EBS root volume
# [FINDING] CKV_AWS_126 — EC2 instance detailed monitoring disabled
# -----------------------------------------------------------------------------
resource "aws_instance" "insecure_ec2" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.micro"

  # BAD: uses the insecure SG from above
  vpc_security_group_ids = [aws_security_group.insecure_sg.id]

  # BAD: IMDSv1 tokens not required — allows SSRF to steal IAM credentials
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "optional" # should be "required" for IMDSv2
    http_put_response_hop_limit = 1
  }

  # BAD: monitoring disabled → no CloudWatch detailed metrics
  monitoring = false

  # BAD: root volume has no encryption
  root_block_device {
    volume_size = 20
    encrypted   = false # [FINDING] CKV_AWS_8 / CKV_AWS_135
  }

  # BAD: public IP assigned → instance reachable from the internet
  associate_public_ip_address = true

  tags = {
    Name = "insecure-ec2"
  }
}


# -----------------------------------------------------------------------------
# [FINDING] CKV_AWS_17 — RDS instance is publicly accessible
# [FINDING] CKV_AWS_16 — RDS instance storage is not encrypted
# [FINDING] CKV_AWS_133 — RDS instance does not have IAM authentication enabled
# [FINDING] CKV_AWS_129 — RDS instance does not have logging enabled
# -----------------------------------------------------------------------------
resource "aws_db_instance" "insecure_rds" {
  identifier        = "insecure-rds"
  engine            = "mysql"
  engine_version    = "8.0"
  instance_class    = "db.t3.micro"
  allocated_storage = 20
  db_name           = "demoapp"

  # BAD: hardcoded credentials in plaintext (also flagged by git-secrets / trufflehog)
  username = "admin"
  password = "SuperSecret123!" # [FINDING] CKV_SECRET / hardcoded secret

  # BAD: database reachable from the public internet
  publicly_accessible = true  # [FINDING] CKV_AWS_17

  # BAD: data at rest is unencrypted
  storage_encrypted = false   # [FINDING] CKV_AWS_16

  # BAD: no automated backups
  backup_retention_period = 0

  # BAD: deletion protection disabled
  deletion_protection = false # [FINDING] CKV_AWS_157

  skip_final_snapshot = true

  tags = {
    Name = "insecure-rds"
  }
}


# -----------------------------------------------------------------------------
# [FINDING] CKV_AWS_7 — IAM role has wildcard (*) actions / resources
# Overly permissive IAM policy grants full AWS access
# -----------------------------------------------------------------------------
resource "aws_iam_role_policy" "insecure_policy" {
  name = "insecure-full-access-policy"
  role = aws_iam_role.insecure_role.id

  # BAD: Action * on Resource * = effectively root-level permissions
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"        # [FINDING] CKV_AWS_7
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role" "insecure_role" {
  name = "insecure-demo-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "ec2.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }
    ]
  })
}


# -----------------------------------------------------------------------------
# [FINDING] CKV_AWS_111 — CloudTrail does not have log file validation enabled
# [FINDING] CKV_AWS_36  — CloudTrail is not encrypted with KMS
# [FINDING] CKV_AWS_67  — CloudTrail is not multi-region
# -----------------------------------------------------------------------------
resource "aws_cloudtrail" "insecure_trail" {
  name                          = "insecure-trail"
  s3_bucket_name                = aws_s3_bucket.insecure_public_bucket.id
  include_global_service_events = false

  # BAD: integrity validation disabled → logs can be tampered undetected
  enable_log_file_validation = false # [FINDING] CKV_AWS_111

  # BAD: single-region trail misses global events
  is_multi_region_trail = false      # [FINDING] CKV_AWS_67

  # BAD: no KMS encryption for log data
  # kms_key_id not set              → [FINDING] CKV_AWS_36

  tags = {
    Name = "insecure-trail"
  }
}
