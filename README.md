# dify-aws-terraform

Terraform template for Dify on AWS

## Prerequisites

- Terraform

## Usage

1. Clone this repository
2. Edit `terraform.tfvars` to set your variables
3. Edit `backend.tf` to set your S3 bucket and DynamoDB table
4. Run `terraform init`
5. Run `terraform plan`
6. Run `terraform apply -target aws_elasticache_subnet_group.redis`
7. Run `terraform apply -target aws_rds_cluster_instance.dify`
8. Run `terraform apply -target aws_lb_listener_rule.api`
9. Run `terraform apply`
