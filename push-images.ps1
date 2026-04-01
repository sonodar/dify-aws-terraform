<#
.SYNOPSIS
    Pulls Dify images from Docker Hub and pushes them to your private ECR repositories.

.DESCRIPTION
    Run this script once after 'terraform apply' has created the ECR repositories.
    Prerequisites: AWS CLI, Docker Desktop (running), and valid AWS credentials.

.PARAMETER AwsRegion
    AWS region where ECR repositories live. Defaults to the value in terraform.tfvars
    or the AWS_DEFAULT_REGION environment variable.

.PARAMETER AwsProfile
    AWS CLI profile to use. No defaults (it should match main.tf provider).

.EXAMPLE
    .\push-images.ps1
    .\push-images.ps1 -AwsRegion ap-east-1 -AwsProfile my-profile
#>

param(
    [string]$AwsRegion
    [string]$AwsProfile
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# Image versions — keep in sync with variables.tf defaults (or override here)
# ---------------------------------------------------------------------------
$images = @(
    @{ Repo = "dify-api";           Source = "langgenius/dify-api:1.13.0"               },
    @{ Repo = "dify-sandbox";       Source = "langgenius/dify-sandbox:0.2.12"            },
    @{ Repo = "dify-plugin-daemon"; Source = "langgenius/dify-plugin-daemon:0.5.3-local" },
    @{ Repo = "dify-web";           Source = "langgenius/dify-web:1.13.0"                },
    @{ Repo = "busybox";            Source = "busybox:latest"                            }
)

# ---------------------------------------------------------------------------
# Resolve region and account ID
# ---------------------------------------------------------------------------
if (-not $AwsRegion) {
    Write-Error "AWS region is required. Pass -AwsRegion or set AWS_DEFAULT_REGION."
}

$accountId = aws sts get-caller-identity --query Account --output text --profile $AwsProfile
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to get AWS account ID. Check your credentials and profile."
}

$ecrBase = "${accountId}.dkr.ecr.${AwsRegion}.amazonaws.com"
Write-Host "ECR base: $ecrBase" -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# Authenticate Docker to ECR (do this in CMD instead, as this gives us error in PowerShell)
# ---------------------------------------------------------------------------
# Write-Host "`nAuthenticating Docker to ECR..." -ForegroundColor Cyan
# aws ecr get-login-password --region $AwsRegion --profile $AwsProfile |
#     docker login --username AWS --password-stdin $ecrBase

# if ($LASTEXITCODE -ne 0) {
#     Write-Error "Docker login to ECR failed."
# }

# ---------------------------------------------------------------------------
# Copy each image from Docker Hub to ECR preserving the linux/arm64 manifest.
#
# WHY NOT docker pull + docker tag + docker push:
#   On a Windows (amd64) host, plain "docker pull" fetches the amd64 layer.
#   Pushing that amd64 image to ECR then causes ECS ARM64 tasks to fail with
#   "exec /bin/bash: exec format error".
#
# APPROACH — two-stage with a fallback:
#   1. docker buildx imagetools create: copies the multi-arch manifest list
#      from Docker Hub straight to ECR with no layer downloads. ECS picks the
#      arm64 digest automatically at launch time. Requires buildx >= 0.9.
#   2. Fallback: docker pull --platform linux/arm64 + push, for older buildx.
# ---------------------------------------------------------------------------
foreach ($img in $images) {
    $source = $img.Source
    $tag    = $source.Split(":")[-1]
    $target = "${ecrBase}/$($img.Repo):${tag}"

    Write-Host "`n--- $($img.Repo) ---" -ForegroundColor Yellow
    Write-Host "  Source : $source"
    Write-Host "  Target : $target"

    Write-Host "  Attempting manifest copy (no layer download)..."
    docker buildx imagetools create --tag $target $source
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  Done (manifest copy)." -ForegroundColor Green
        continue
    }

    Write-Warning "  imagetools failed — falling back to pull --platform linux/arm64"
    docker pull --platform linux/arm64 $source
    if ($LASTEXITCODE -ne 0) { Write-Error "Failed to pull $source for linux/arm64" }

    docker tag $source $target
    if ($LASTEXITCODE -ne 0) { Write-Error "Failed to tag $source -> $target" }

    docker push $target
    if ($LASTEXITCODE -ne 0) { Write-Error "Failed to push $target" }

    Write-Host "  Done (pull+push)." -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# Force new ECS deployments so tasks pick up the ECR images immediately
# ---------------------------------------------------------------------------
Write-Host "`nForcing new ECS deployments..." -ForegroundColor Cyan

$services = @("dify-api", "dify-worker", "dify-sandbox", "dify-plugin-daemon", "dify-web")
foreach ($svc in $services) {
    Write-Host "  Updating service: $svc"
    aws ecs update-service `
        --cluster dify-cluster `
        --service $svc `
        --force-new-deployment `
        --region $AwsRegion `
        --profile $AwsProfile
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "  Could not force-deploy $svc (it may not exist yet — that is OK on first run)."
    }
}

Write-Host "`nAll images pushed successfully to ECR." -ForegroundColor Green
Write-Host "ECS services will pull from ECR on their next task launch." -ForegroundColor Green
