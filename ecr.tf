# ECR Repositories for Dify images
# These mirror Docker Hub langgenius/* images to avoid unauthenticated pull rate limits.

locals {
  ecr_images = ["dify-api", "dify-sandbox", "dify-plugin-daemon", "dify-web", "busybox"]
}

resource "aws_ecr_repository" "dify" {
  for_each = toset(local.ecr_images)

  name                 = each.key
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }
}

resource "aws_ecr_lifecycle_policy" "dify" {
  for_each   = aws_ecr_repository.dify
  repository = each.value.name

  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Expire untagged images after 7 days"
        selection = {
          tagStatus   = "untagged"
          countType   = "sinceImagePushed"
          countUnit   = "days"
          countNumber = 7
        }
        action = {
          type = "expire"
        }
      }
    ]
  })
}
