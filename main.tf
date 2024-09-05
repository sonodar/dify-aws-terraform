provider "aws" {
  region = var.aws_region

  default_tags {
    tags = var.default_tags
  }
}

data "aws_caller_identity" "current" {}

# S3 Bucket for Dify Storage

resource "aws_s3_bucket" "storage" {
  bucket = var.dify_storage_bucket
}

# VPC

data "aws_vpc" "this" {
  id = var.vpc_id
}

# Redis

resource "aws_security_group" "redis" {
  name        = "dify-redis"
  description = "Redis for Dify"
  vpc_id      = var.vpc_id
  tags        = { Name = "dify-redis" }
  # API/Worker からの ingress を下の方で定義している
}

resource "aws_elasticache_subnet_group" "redis" {
  name        = "dify-redis"
  description = "Redis for Dify"
  subnet_ids  = var.private_subnet_ids
}

# MOVED エラーが発生するのでクラスターモードは使わない
resource "aws_elasticache_replication_group" "redis" {
  replication_group_id = "dify"
  description          = "Redis for Dify"

  engine         = "redis"
  engine_version = "7.1"

  node_type = "cache.t4g.micro"

  subnet_group_name  = aws_elasticache_subnet_group.redis.name
  security_group_ids = [aws_security_group.redis.id]

  auto_minor_version_upgrade = true
  at_rest_encryption_enabled = true
  transit_encryption_enabled = true

  auth_token_update_strategy = "SET"
  auth_token                 = var.redis_password

  # auth token を後から変更する場合（ROTATE して SET する）
  # REDIS_PASSWORD='put your redis password'
  # aws elasticache modify-replication-group \
  #   --replication-group-id dify \
  #   --auth-token ${REDIS_PASSWORD} \
  #   --auth-token-update-strategy ROTATE \
  #   --apply-immediately
  # aws elasticache modify-replication-group \
  #   --replication-group-id dify \
  #   --auth-token ${REDIS_PASSWORD} \
  #   --auth-token-update-strategy SET \
  #   --apply-immediately

  maintenance_window       = "sat:18:00-sat:19:00"
  snapshot_window          = "20:00-21:00"
  snapshot_retention_limit = 1

  parameter_group_name = "default.redis7"

  lifecycle {
    ignore_changes = [auth_token]
  }
}

# Database

resource "aws_security_group" "database" {
  name        = "dify-db"
  description = "PostgreSQL for Dify"
  vpc_id      = var.vpc_id
  tags        = { Name = "dify-db" }
  # API/Worker からの ingress を下の方で定義している
}

# S3 バックアップなどでインターネットへのアクセスが必要な場合は egress を追加する。
# VPC Endpoint や Managed Prefix List を使ってインターネットへのアクセスを制限するのがベター。
resource "aws_security_group_rule" "database_to_internet" {
  security_group_id = aws_security_group.database.id
  type              = "egress"
  description       = "Internet"
  protocol          = "all"
  from_port         = 0
  to_port           = 0
  cidr_blocks       = ["0.0.0.0/0"]
}

resource "aws_db_subnet_group" "dify" {
  name        = "dify"
  description = "PostgreSQL for Dify"
  subnet_ids  = var.private_subnet_ids
}

resource "aws_rds_cluster" "dify" {
  cluster_identifier = "dify"

  engine         = "aurora-postgresql"
  engine_version = "15.4"
  port           = 5432

  db_subnet_group_name            = aws_db_subnet_group.dify.name
  db_cluster_parameter_group_name = "default.aurora-postgresql15"
  vpc_security_group_ids          = [aws_security_group.database.id]

  master_username = "postgres"
  master_password = var.db_master_password

  # データベースは後から構築する
  # -- CREATE ROLE dify WITH LOGIN PASSWORD 'password';
  # -- GRANT dify TO postgres;
  # -- CREATE DATABASE dify WITH OWNER dify;
  # -- \c dify
  # -- CREATE EXTENSION vector;

  # 上記 SQL をマネジメントコンソールのクエリエディタで実行する場合は HTTP エンドポイントを有効にする。
  # エンドポイントを有効にしない場合は踏み台インスタンスなどを用意して上記 SQL を実行する。
  enable_http_endpoint = true

  backup_retention_period  = 7
  delete_automated_backups = true

  preferred_backup_window      = "13:29-13:59"
  preferred_maintenance_window = "sat:18:00-sat:19:00"
  skip_final_snapshot          = true
  storage_encrypted            = true
  copy_tags_to_snapshot        = true

  serverlessv2_scaling_configuration {
    min_capacity = 2
    max_capacity = 4
  }

  lifecycle {
    ignore_changes = [engine_version, master_password]
  }
}

resource "aws_rds_cluster_instance" "dify" {
  identifier = "dify-instance-1"

  cluster_identifier = aws_rds_cluster.dify.cluster_identifier
  engine             = aws_rds_cluster.dify.engine
  engine_version     = aws_rds_cluster.dify.engine_version
  instance_class     = "db.serverless"

  auto_minor_version_upgrade = true
  promotion_tier             = 1

  db_parameter_group_name = "default.aurora-postgresql15"
  db_subnet_group_name    = aws_db_subnet_group.dify.name

  performance_insights_enabled          = true
  performance_insights_retention_period = 7
}

# Execution Role

data "aws_iam_policy_document" "ecs_task" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "get_secret" {
  statement {
    actions   = ["ssm:GetParameter", "ssm:GetParameters"]
    resources = ["arn:aws:ssm:*:${data.aws_caller_identity.current.account_id}:parameter/*"]
  }
}

resource "aws_iam_role" "exec" {
  name               = "dify-task-execution-role"
  description        = "AmazonECSTaskExecutionRole for Dify"
  assume_role_policy = data.aws_iam_policy_document.ecs_task.json
}
resource "aws_iam_role_policy_attachment" "AmazonECSTaskExecutionRolePolicy" {
  role       = aws_iam_role.exec.id
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}
resource "aws_iam_role_policy" "get_secret" {
  role   = aws_iam_role.exec.id
  name   = "get-secret"
  policy = data.aws_iam_policy_document.get_secret.json
}

# Task Role Basic Policy

data "aws_iam_policy_document" "ecs_base" {
  statement {
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:DescribeLogStreams",
      "logs:DescribeLogGroups",
      "logs:PutLogEvents",
      "xray:PutTelemetryRecords",
      "xray:PutTraceSegments",
      # ECS execute-command
      # https://dev.classmethod.jp/articles/ecs-exec/
      # "ssmmessages:CreateControlChannel",
      # "ssmmessages:CreateDataChannel",
      # "ssmmessages:OpenControlChannel",
      # "ssmmessages:OpenDataChannel",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "ecs_base" {
  name        = "dify-task-base-policy"
  description = "Base policy for Dify ECS tasks"
  policy      = data.aws_iam_policy_document.ecs_base.json
}

# Log Group

# ロググループは全コンテナ共通にしているが、運用を考えるとコンテナごとに分けた方がいいと思う。
resource "aws_cloudwatch_log_group" "dify" {
  name              = "/dify/container-logs"
  retention_in_days = 30 # TODO: variable
}

# Dependencies for API + Sandbox and Worker task

locals {
  ssm_parameter_prefix = "/dify"
}

# セキュアにするなら Credentials は Terraform で管理しない方がいいと思う。
resource "random_password" "sandbox_key" {
  length           = 42
  special          = true
  override_special = "%&-_=+:/"
}

resource "aws_ssm_parameter" "sandbox_key" {
  type  = "SecureString"
  name  = "${local.ssm_parameter_prefix}/SANDBOX_API_KEY"
  value = random_password.sandbox_key.result
}

resource "random_password" "session_secret_key" {
  length           = 42
  special          = true
  override_special = "-_=+/"
}

resource "aws_ssm_parameter" "session_secret_key" {
  type  = "SecureString"
  name  = "${local.ssm_parameter_prefix}/SESSION_SECRET_KEY"
  value = random_password.session_secret_key.result
  lifecycle {
    ignore_changes = [value]
  }
}

resource "aws_ssm_parameter" "db_password" {
  type  = "SecureString"
  name  = "${local.ssm_parameter_prefix}/DB_PASSWORD"
  value = var.dify_db_password
  lifecycle {
    ignore_changes = [value]
  }
}

resource "aws_ssm_parameter" "redis_password" {
  type  = "SecureString"
  name  = "${local.ssm_parameter_prefix}/REDIS_PASSWORD"
  value = var.redis_password
  lifecycle {
    ignore_changes = [value]
  }
}

# Broker URL はパスワードを含むためシークレットにする
resource "aws_ssm_parameter" "broker_url" {
  depends_on = [aws_elasticache_replication_group.redis]
  type       = "SecureString"
  name       = "${local.ssm_parameter_prefix}/CELERY_BROKER_URL"
  value      = "rediss://:${var.redis_password}@${aws_elasticache_replication_group.redis.primary_endpoint_address}:6379/0" # ElastiCache Redis では db0 以外使えない
  lifecycle {
    # ignore_changes = [value]
  }
}

data "aws_iam_policy_document" "storage" {
  statement {
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.storage.arn]
  }
  statement {
    actions   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
    resources = ["${aws_s3_bucket.storage.arn}/*"]
  }
}

data "aws_iam_policy_document" "bedrock" {
  statement {
    actions   = ["bedrock:InvokeModel"]
    resources = ["arn:aws:bedrock:*::foundation-model/*"]
  }
}

resource "aws_iam_role" "app" {
  name               = "dify-app-task-role"
  description        = "Task Role for Dify API, Worker and Sandbox"
  assume_role_policy = data.aws_iam_policy_document.ecs_task.json
}
resource "aws_iam_role_policy_attachment" "ecs_base_app" {
  role       = aws_iam_role.app.id
  policy_arn = aws_iam_policy.ecs_base.arn
}
resource "aws_iam_role_policy" "s3_storage" {
  role   = aws_iam_role.app.id
  name   = "s3-storage"
  policy = data.aws_iam_policy_document.storage.json
}
resource "aws_iam_role_policy" "bedrock" {
  role   = aws_iam_role.app.id
  name   = "invoke-bedrock-model"
  policy = data.aws_iam_policy_document.bedrock.json
}

# Dify API (with Sandbox) Task

resource "aws_ecs_task_definition" "dify_api" {
  family                   = "dify-api"
  execution_role_arn       = aws_iam_role.exec.arn
  task_role_arn            = aws_iam_role.app.arn
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = 1024 # TODO: variable
  memory                   = 2048 # TODO: variable

  volume {
    name = "dependencies"
  }

  container_definitions = jsonencode([
    {
      name      = "dify-api"
      image     = "langgenius/dify-api:${var.dify_api_version}"
      essential = true
      portMappings = [
        {
          hostPort      = 5001
          protocol      = "tcp"
          containerPort = 5001
        }
      ]
      environment = [
        for name, value in {
          # Startup mode, 'api' starts the API server.
          MODE = "api"
          # The log level for the application. Supported values are `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`
          LOG_LEVEL = "INFO"
          # enable DEBUG mode to output more logs
          # DEBUG  = "true"
          # The base URL of console application web frontend, refers to the Console base URL of WEB service if console domain is
          # different from api or web app domain.
          # example: http://cloud.dify.ai
          CONSOLE_WEB_URL = "http://${aws_lb.dify.dns_name}"
          # The base URL of console application api server, refers to the Console base URL of WEB service if console domain is different from api or web app domain.
          # example: http://cloud.dify.ai
          CONSOLE_API_URL = "http://${aws_lb.dify.dns_name}"
          # The URL prefix for Service API endpoints, refers to the base URL of the current API service if api domain is different from console domain.
          # example: http://api.dify.ai
          SERVICE_API_URL = "http://${aws_lb.dify.dns_name}"
          # The URL prefix for Web APP frontend, refers to the Web App base URL of WEB service if web app domain is different from console or api domain.
          # example: http://udify.app
          APP_WEB_URL = "http://${aws_lb.dify.dns_name}"
          # When enabled, migrations will be executed prior to application startup and the application will start after the migrations have completed.
          MIGRATION_ENABLED = var.migration_enabled
          # The configurations of postgres database connection.
          # It is consistent with the configuration in the 'db' service below.
          DB_USERNAME = var.dify_db_username
          DB_HOST     = aws_rds_cluster.dify.endpoint
          DB_PORT     = aws_rds_cluster.dify.port
          DB_DATABASE = var.dify_db_name
          # The configurations of redis connection.
          # It is consistent with the configuration in the 'redis' service below.
          REDIS_HOST    = aws_elasticache_replication_group.redis.primary_endpoint_address
          REDIS_PORT    = aws_elasticache_replication_group.redis.port
          REDIS_USE_SSL = true
          # use redis db 0 for redis cache
          REDIS_DB = 0
          # Specifies the allowed origins for cross-origin requests to the Web API, e.g. https://dify.app or * for all origins.
          WEB_API_CORS_ALLOW_ORIGINS = "*"
          # Specifies the allowed origins for cross-origin requests to the console API, e.g. https://cloud.dify.ai or * for all origins.
          CONSOLE_CORS_ALLOW_ORIGINS = "*"
          # CSRF Cookie settings
          # Controls whether a cookie is sent with cross-site requests,
          # providing some protection against cross-site request forgery attacks
          #
          # Default = `SameSite=Lax, Secure=false, HttpOnly=true`
          # This default configuration supports same-origin requests using either HTTP or HTTPS,
          # but does not support cross-origin requests. It is suitable for local debugging purposes.
          #
          # If you want to enable cross-origin support,
          # you must use the HTTPS protocol and set the configuration to `SameSite=None, Secure=true, HttpOnly=true`.
          #
          # The type of storage to use for storing user files. Supported values are `local` and `s3` and `azure-blob` and `google-storage`, Default = `local`
          STORAGE_TYPE = "s3"
          # The S3 storage configurations, only available when STORAGE_TYPE is `s3`.
          S3_USE_AWS_MANAGED_IAM = true
          S3_BUCKET_NAME         = aws_s3_bucket.storage.bucket
          S3_REGION              = var.aws_region
          # The type of vector store to use. Supported values are `weaviate`, `qdrant`, `milvus`, `relyt`.
          VECTOR_STORE = "pgvector"
          # pgvector configurations
          PGVECTOR_HOST     = aws_rds_cluster.dify.endpoint
          PGVECTOR_PORT     = aws_rds_cluster.dify.port
          PGVECTOR_USER     = "dify"
          PGVECTOR_DATABASE = "dify"
          # # Mail configuration, support = resend, smtp
          # MAIL_TYPE = ''
          # # default send from email address, if not specified
          # MAIL_DEFAULT_SEND_FROM = 'YOUR EMAIL FROM (eg = no-reply <no-reply@dify.ai>)'
          # SMTP_SERVER = ''
          # SMTP_PORT = 587
          # SMTP_USERNAME = ''
          # SMTP_PASSWORD = ''
          # SMTP_USE_TLS = 'true'
          # The sandbox service endpoint.
          CODE_EXECUTION_ENDPOINT       = "http://localhost:8194" # Fargate の task 内通信は localhost 宛
          CODE_MAX_NUMBER               = "9223372036854775807"
          CODE_MIN_NUMBER               = "-9223372036854775808"
          CODE_MAX_STRING_LENGTH        = 80000
          TEMPLATE_TRANSFORM_MAX_LENGTH = 80000
          CODE_MAX_STRING_ARRAY_LENGTH  = 30
          CODE_MAX_OBJECT_ARRAY_LENGTH  = 30
          CODE_MAX_NUMBER_ARRAY_LENGTH  = 1000
          # Indexing configuration
          INDEXING_MAX_SEGMENTATION_TOKENS_LENGTH = 1000
        } : { name = name, value = tostring(value) }
      ]
      secrets = [
        {
          name      = "SECRET_KEY"
          valueFrom = aws_ssm_parameter.session_secret_key.name
        },
        {
          name      = "DB_PASSWORD"
          valueFrom = aws_ssm_parameter.db_password.name
        },
        {
          name      = "REDIS_PASSWORD"
          valueFrom = aws_ssm_parameter.redis_password.name
        },
        # The configurations of celery broker.
        # Use redis as the broker, and redis db 1 for celery broker.
        {
          name      = "CELERY_BROKER_URL"
          valueFrom = aws_ssm_parameter.broker_url.name
        },
        {
          name      = "PGVECTOR_PASSWORD"
          valueFrom = aws_ssm_parameter.db_password.name
        },
        {
          name      = "CODE_EXECUTION_API_KEY"
          valueFrom = aws_ssm_parameter.sandbox_key.name
        }
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.dify.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "dify-api"
        }
      }
      healthCheck = {
        command     = ["CMD-SHELL", "curl -f http://localhost:5001/health || exit 1"]
        interval    = 10
        timeout     = 5
        retries     = 3
        startPeriod = 30
      }
      cpu         = 0
      volumesFrom = []
      mountPoints = []
    },
    // `dify-sandbox:0.2.6` では `/dependencies/python-requirements.txt` が存在しないと起動時エラーになる。
    // そのため、簡易的ではあるが volume を利用して sandbox から見れるファイルを作成する。
    {
      name      = "dify-sandbox-dependencies"
      image     = "busybox:latest" # dify-sandbox イメージより軽量ならなんでもいい
      essential = false
      cpu       = 0
      mountPoints = [
        {
          sourceVolume  = "dependencies"
          containerPath = "/dependencies"
        }
      ]
      entryPoint = ["sh", "-c"]
      command    = ["touch /dependencies/python-requirements.txt && chmod 755 /dependencies/python-requirements.txt"]
    },
    {
      name      = "dify-sandbox"
      image     = "langgenius/dify-sandbox:${var.dify_sandbox_version}"
      essential = true
      mountPoints = [
        {
          sourceVolume  = "dependencies"
          containerPath = "/dependencies"
        }
      ]
      portMappings = [
        {
          hostPort      = 8194
          protocol      = "tcp"
          containerPort = 8194
        }
      ]
      environment = [
        for name, value in {
          GIN_MODE       = "release"
          WORKER_TIMEOUT = 15
          ENABLE_NETWORK = true
          SANDBOX_PORT   = 8194
        } : { name = name, value = tostring(value) }
      ]
      secrets = [
        {
          name      = "API_KEY"
          valueFrom = aws_ssm_parameter.sandbox_key.name
        }
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.dify.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "dify-sandbox"
        }
      }
      cpu         = 0
      volumesFrom = []
    },
  ])

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "ARM64"
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group" "api" {
  name        = "dify-api"
  description = "Dify API"
  vpc_id      = var.vpc_id
  tags        = { Name = "dify-api" }
}

# TODO: 公式では SSRF 対策のために Forward Proxy として squid をプロビジョニングしているが、
# 本構成では SSRF 対策の Forward Proxy は省略している。必要な場合は squid のタスクを用意したり、Firewall Manager などを利用する。
resource "aws_security_group_rule" "api_to_internet" {
  security_group_id = aws_security_group.api.id
  type              = "egress"
  description       = "Internet"
  protocol          = "all"
  from_port         = 0
  to_port           = 0
  cidr_blocks       = ["0.0.0.0/0"]
}

resource "aws_security_group_rule" "alb_to_api" {
  security_group_id        = aws_security_group.api.id
  type                     = "ingress"
  description              = "ALB to API"
  protocol                 = "tcp"
  from_port                = 5001
  to_port                  = 5001
  source_security_group_id = aws_security_group.alb.id
}

resource "aws_security_group_rule" "api_to_database" {
  security_group_id        = aws_security_group.database.id
  type                     = "ingress"
  description              = "API to Database"
  protocol                 = "tcp"
  from_port                = 5432
  to_port                  = 5432
  source_security_group_id = aws_security_group.api.id
}

resource "aws_security_group_rule" "api_to_redis" {
  security_group_id        = aws_security_group.redis.id
  type                     = "ingress"
  description              = "API to Redis"
  protocol                 = "tcp"
  from_port                = 6379
  to_port                  = 6379
  source_security_group_id = aws_security_group.api.id
}


# Dify Worker Task
resource "aws_ecs_task_definition" "dify_worker" {
  family                   = "dify-worker"
  execution_role_arn       = aws_iam_role.exec.arn
  task_role_arn            = aws_iam_role.app.arn
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = 1024 # TODO: variable
  memory                   = 2048 # TODO: variable

  container_definitions = jsonencode([
    {
      name      = "dify-worker"
      image     = "langgenius/dify-api:${var.dify_api_version}"
      essential = true
      environment = [
        for name, value in {
          # Startup mode, 'worker' starts the Celery worker for processing the queue.
          MODE = "worker"

          # --- All the configurations below are the same as those in the 'api' service. ---

          # The log level for the application. Supported values are `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`
          LOG_LEVEL = "INFO"
          # The configurations of postgres database connection.
          # It is consistent with the configuration in the 'db' service below.
          DB_USERNAME = var.dify_db_username
          DB_HOST     = aws_rds_cluster.dify.endpoint
          DB_PORT     = aws_rds_cluster.dify.port
          DB_DATABASE = var.dify_db_name
          # The configurations of redis cache connection.
          REDIS_HOST    = aws_elasticache_replication_group.redis.primary_endpoint_address
          REDIS_PORT    = aws_elasticache_replication_group.redis.port
          REDIS_DB      = "0"
          REDIS_USE_SSL = "true"
          # The type of storage to use for storing user files. Supported values are `local` and `s3` and `azure-blob` and `google-storage`, Default = `local`
          STORAGE_TYPE = "s3"
          # The S3 storage configurations, only available when STORAGE_TYPE is `s3`.
          S3_USE_AWS_MANAGED_IAM = true
          S3_BUCKET_NAME         = aws_s3_bucket.storage.bucket
          S3_REGION              = var.aws_region
          # The type of vector store to use. Supported values are `weaviate`, `qdrant`, `milvus`, `relyt`, `pgvector`.
          VECTOR_STORE = "pgvector"
          # pgvector configurations
          PGVECTOR_HOST     = aws_rds_cluster.dify.endpoint
          PGVECTOR_PORT     = aws_rds_cluster.dify.port
          PGVECTOR_USER     = "dify"
          PGVECTOR_DATABASE = "dify"
          # Mail configuration, support = resend
          # MAIL_TYPE = ''
          # # default send from email address, if not specified
          # MAIL_DEFAULT_SEND_FROM = 'YOUR EMAIL FROM (eg = no-reply <no-reply@dify.ai>)'
          # SMTP_SERVER = ''
          # SMTP_PORT = 587
          # SMTP_USERNAME = ''
          # SMTP_PASSWORD = ''
          # SMTP_USE_TLS = 'true'
          # Indexing configuration
          INDEXING_MAX_SEGMENTATION_TOKENS_LENGTH = "1000"
        } : { name = name, value = tostring(value) }
      ]
      secrets = [
        {
          name      = "SECRET_KEY"
          valueFrom = aws_ssm_parameter.session_secret_key.name
        },
        {
          name      = "DB_PASSWORD"
          valueFrom = aws_ssm_parameter.db_password.name
        },
        {
          name      = "REDIS_PASSWORD"
          valueFrom = aws_ssm_parameter.redis_password.name
        },
        # The configurations of celery broker.
        # Use redis as the broker, and redis db 1 for celery broker.
        {
          name      = "CELERY_BROKER_URL"
          valueFrom = aws_ssm_parameter.broker_url.name
        },
        {
          name      = "PGVECTOR_PASSWORD"
          valueFrom = aws_ssm_parameter.db_password.name
        }
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.dify.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "dify-worker"
        }
      }
      cpu         = 0
      volumesFrom = []
      mountPoints = []
    },
  ])

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "ARM64"
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group" "worker" {
  name        = "dify-worker"
  description = "Dify Worker"
  vpc_id      = var.vpc_id
  tags        = { Name = "dify-worker" }
}

resource "aws_security_group_rule" "worker_to_internet" {
  security_group_id = aws_security_group.worker.id
  type              = "egress"
  description       = "Internet"
  protocol          = "all"
  from_port         = 0
  to_port           = 0
  cidr_blocks       = ["0.0.0.0/0"]
}

resource "aws_security_group_rule" "worker_to_database" {
  security_group_id        = aws_security_group.database.id
  type                     = "ingress"
  description              = "Worker to Database"
  protocol                 = "tcp"
  from_port                = 5432
  to_port                  = 5432
  source_security_group_id = aws_security_group.worker.id
}

resource "aws_security_group_rule" "worker_to_redis" {
  security_group_id        = aws_security_group.redis.id
  type                     = "ingress"
  description              = "Worker to Redis"
  protocol                 = "tcp"
  from_port                = 6379
  to_port                  = 6379
  source_security_group_id = aws_security_group.worker.id
}

# Dify Web Task

resource "aws_iam_role" "web" {
  name               = "dify-web-task-role"
  description        = "Task Role for Dify Web"
  assume_role_policy = data.aws_iam_policy_document.ecs_task.json
}
resource "aws_iam_role_policy_attachment" "ecs_base_web" {
  role       = aws_iam_role.web.id
  policy_arn = aws_iam_policy.ecs_base.arn
}

resource "aws_ecs_task_definition" "dify_web" {
  family                   = "dify-web"
  execution_role_arn       = aws_iam_role.exec.arn
  task_role_arn            = aws_iam_role.web.arn
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = 1024 # TODO: variable
  memory                   = 2048 # TODO: variable

  container_definitions = jsonencode([
    {
      name      = "dify-web"
      image     = "langgenius/dify-web:${var.dify_web_version}"
      essential = true
      environment = [
        for name, value in {
          # The base URL of console application api server, refers to the Console base URL of WEB service if console domain is
          # different from api or web app domain.
          # example: http://cloud.dify.ai
          CONSOLE_API_URL = "http://${aws_lb.dify.dns_name}"
          # # The URL for Web APP api server, refers to the Web App base URL of WEB service if web app domain is different from
          # # console or api domain.
          # # example: http://udify.app
          APP_API_URL = "http://${aws_lb.dify.dns_name}"
          NEXT_TELEMETRY_DISABLED = "0"
        } : { name = name, value = tostring(value) }
      ]
      portMappings = [
        {
          hostPort      = 3000
          protocol      = "tcp"
          containerPort = 3000
        }
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.dify.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "dify-web"
        }
      }
      cpu         = 0
      volumesFrom = []
      mountPoints = []
    },
  ])

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "ARM64"
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group" "web" {
  name        = "dify-web"
  description = "Dify Web"
  vpc_id      = var.vpc_id
  tags        = { Name = "dify-web" }
}

# インターネットアクセスは不要だが、これがないと ECR からイメージのダウンロードに失敗して
# タスクの起動がエラーになる。VPC エンドポイントを作成できるならそちらの方がベター。
resource "aws_security_group_rule" "web_to_internet" {
  security_group_id = aws_security_group.web.id
  type              = "egress"
  description       = "Web to Internet"
  protocol          = "all"
  from_port         = 0
  to_port           = 0
  cidr_blocks       = ["0.0.0.0/0"]
}

resource "aws_security_group_rule" "alb_to_web" {
  security_group_id        = aws_security_group.web.id
  type                     = "ingress"
  description              = "ALB to Web"
  protocol                 = "tcp"
  from_port                = 3000
  to_port                  = 3000
  source_security_group_id = aws_security_group.alb.id
}

# ALB

resource "aws_security_group" "alb" {
  name        = "dify-alb"
  description = "ALB (Reverse Proxy) for Dify"
  vpc_id      = var.vpc_id
  tags        = { Name = "dify-alb" }
}

resource "aws_security_group_rule" "alb_to_targetgroup" {
  security_group_id = aws_security_group.alb.id
  type              = "egress"
  description       = "ALB to TargetGroup"
  protocol          = "all"
  from_port         = 0
  to_port           = 0
  cidr_blocks       = [data.aws_vpc.this.cidr_block]
}

resource "aws_security_group_rule" "http_from_internet" {
  security_group_id = aws_security_group.alb.id
  type              = "ingress"
  description       = "HTTP from Internet"
  protocol          = "tcp"
  from_port         = 80
  to_port           = 80
  cidr_blocks       = var.allowed_cidr_blocks
}

resource "aws_lb" "dify" {
  name               = "dify-alb"
  load_balancer_type = "application"
  subnets            = var.public_subnet_ids
  security_groups    = [aws_security_group.alb.id]
}

# ALB Listener (HTTP)

resource "aws_lb_target_group" "web" {
  name        = "dify-web"
  vpc_id      = var.vpc_id
  protocol    = "HTTP"
  port        = 3000
  target_type = "ip"

  slow_start           = 0
  deregistration_delay = 65

  health_check {
    path     = "/apps" # "/" だと 307 になる
    interval = 10
    # timeout             = 5
    # healthy_threshold   = 3
    # unhealthy_threshold = 5
  }
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.dify.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.web.arn
  }
}

# ALB Listener Rule (API)
# path pattern によって API に振り分ける

locals {
  api_paths = ["/console/api", "/api", "/v1", "/files"]
}

resource "aws_lb_listener_rule" "api" {
  listener_arn = aws_lb_listener.http.arn
  priority     = 10

  condition {
    path_pattern {
      values = local.api_paths
    }
  }

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.api.arn
  }
}

resource "aws_lb_listener_rule" "api_wildcard" {
  listener_arn = aws_lb_listener.http.arn
  priority     = 11

  condition {
    path_pattern {
      values = [for path in local.api_paths : "${path}/*"]
    }
  }

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.api.arn
  }
}

resource "aws_lb_target_group" "api" {
  name        = "dify-api"
  vpc_id      = var.vpc_id
  protocol    = "HTTP"
  port        = 5001
  target_type = "ip"

  slow_start           = 0
  deregistration_delay = 65

  health_check {
    path     = "/health"
    interval = 10
    # timeout             = 5
    # healthy_threshold   = 3
    # unhealthy_threshold = 5
  }
}

# ECS Cluster

resource "aws_ecs_cluster" "dify" {
  name = "dify-cluster"
  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}
// AutoScaling などで FARGATE_SPOT を使う場合は追加しておく
resource "aws_ecs_cluster_capacity_providers" "this" {
  cluster_name       = aws_ecs_cluster.dify.name
  capacity_providers = ["FARGATE", "FARGATE_SPOT"]
}

# ECS Service

resource "aws_ecs_service" "api" {
  depends_on      = [aws_lb_listener_rule.api] # ターゲットグループが ALB と紐付いていないと構築時にエラーになる
  name            = "dify-api"
  cluster         = aws_ecs_cluster.dify.name
  desired_count   = var.api_desired_count
  task_definition = aws_ecs_task_definition.dify_api.arn
  propagate_tags  = "SERVICE"
  launch_type     = "FARGATE"

  network_configuration {
    subnets         = var.private_subnet_ids
    security_groups = [aws_security_group.api.id]
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.api.arn
    container_name   = "dify-api"
    container_port   = 5001
  }
}

resource "aws_ecs_service" "worker" {
  name            = "dify-worker"
  cluster         = aws_ecs_cluster.dify.name
  desired_count   = var.worker_desired_count
  task_definition = aws_ecs_task_definition.dify_worker.arn
  propagate_tags  = "SERVICE"
  launch_type     = "FARGATE"

  network_configuration {
    subnets         = var.private_subnet_ids
    security_groups = [aws_security_group.worker.id]
  }
}

resource "aws_ecs_service" "web" {
  name            = "dify-web"
  cluster         = aws_ecs_cluster.dify.name
  desired_count   = var.web_desired_count
  task_definition = aws_ecs_task_definition.dify_web.arn
  propagate_tags  = "SERVICE"
  launch_type     = "FARGATE"

  network_configuration {
    subnets         = var.private_subnet_ids
    security_groups = [aws_security_group.web.id]
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.web.arn
    container_name   = "dify-web"
    container_port   = 3000
  }
}
