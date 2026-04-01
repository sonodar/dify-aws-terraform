# AWS Provider

variable "aws_region" {}

variable "default_tags" {
  type = map(string)
}

# S3 Bucket for Dify Storage

variable "dify_storage_bucket" {
  description = "s3 bucket name for dify storage"
}

# VPC – networking is now managed in vpc.tf; IDs are exposed via locals.

# Redis

variable "redis_password" {
  default   = "redis_dummy_auth_token"
  sensitive = true
  # 初回実行時は dummy で実行し、構築後に以下のコマンドで更新する。
  # aws elasticache modify-replication-group \
  # --replication-group-id replication-group-sample \
  # --auth-token new-token \
  # --auth-token-update-strategy SET \
  # --apply-immediately
}

# Database

variable "db_master_password" {
  default   = "dummy" # 初回実行時に TF_VAR_db_master_password=xxx で与える
  sensitive = true
}

# Dify environment

variable "dify_api_version" {
  default = "1.13.0"
}

variable "dify_web_version" {
  default = "1.13.0"
}

variable "dify_sandbox_version" {
  default = "0.2.12"
}

variable "dify_plugin_daemon_version" {
  default = "0.5.3-local"
}

variable "migration_enabled" {
  default = "true"
}

variable "dify_db_username" {
  default = "dify"
}
variable "dify_db_password" {
  default   = "dummy"
  sensitive = true
}
variable "dify_db_name" {
  default = "dify"
}

# ALB

variable "allowed_cidr_blocks" {
  type        = list(string)
  default     = ["0.0.0.0/0"]
  description = "CIDR blocks allowed to reach the ALB on HTTP (e.g. [\"1.2.3.4/32\"] to restrict). Default allows all."
}

# Service

variable "api_desired_count" {
  default = 1
}

variable "worker_desired_count" {
  default = 1
}

variable "web_desired_count" {
  default = 1
}

variable "plugin_daemon_desired_count" {
  default = 1
}

variable "sandbox_desired_count" {
  default = 1
}
