# AWS Provider

variable "aws_region" {}

variable "default_tags" {
  type = map(string)
}

# S3 Bucket for Dify Storage

variable "dify_storage_bucket" {
  description = "s3 bucket name for dify storage"
}

# VPC

variable "vpc_id" {
}
variable "private_subnet_ids" {
  type = list(string)
}
variable "public_subnet_ids" {
  type = list(string)
}

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
  default = "0.7.3"
}

variable "dify_web_version" {
  default = "0.7.3"
}

variable "dify_sandbox_version" {
  default = "0.2.6"
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
  type    = list(string)
  default = []
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
