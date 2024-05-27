# S3 Bucket for Dify Storage

output "storage_bucket_arn" {
  value = aws_s3_bucket.storage.arn
}

# Redis

output "redis_endpoint" {
  value = aws_elasticache_replication_group.redis.configuration_endpoint_address
}

output "redis_port" {
  value = aws_elasticache_replication_group.redis.port
}

# Database

output "db_host" {
  value = aws_rds_cluster.dify.endpoint
}

output "db_port" {
  value = aws_rds_cluster.dify.port
}

# Endpint

output "dify_url" {
  value = "http://${aws_lb.dify.dns_name}"
}
