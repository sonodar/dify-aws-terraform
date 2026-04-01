# ---------------------------------------------------------------------------
# VPC networking for Dify on AWS
# ---------------------------------------------------------------------------

# Discover the two available AZs in the target region automatically so this
# file works without hard-coding AZ names.
data "aws_availability_zones" "available" {
  state = "available"
}

# ---------------------------------------------------------------------------
# Variables – CIDR blocks are the only knobs you normally need to touch.
# ---------------------------------------------------------------------------

variable "vpc_cidr" {
  description = "CIDR block for the Dify VPC"
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidrs" {
  description = "CIDR blocks for the two public subnets (one per AZ)"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24"]
}

variable "private_subnet_cidrs" {
  description = "CIDR blocks for the two private subnets (one per AZ)"
  type        = list(string)
  default     = ["10.0.10.0/24", "10.0.20.0/24"]
}

# ---------------------------------------------------------------------------
# VPC
# ---------------------------------------------------------------------------

resource "aws_vpc" "dify" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = "dify-vpc" }
}

# ---------------------------------------------------------------------------
# Internet Gateway
# ---------------------------------------------------------------------------

resource "aws_internet_gateway" "dify" {
  vpc_id = aws_vpc.dify.id

  tags = { Name = "dify-igw" }
}

# ---------------------------------------------------------------------------
# Public subnets
# ---------------------------------------------------------------------------

resource "aws_subnet" "public" {
  count = 2

  vpc_id                  = aws_vpc.dify.id
  cidr_block              = var.public_subnet_cidrs[count.index]
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true

  tags = { Name = "dify-public-${count.index + 1}" }
}

# ---------------------------------------------------------------------------
# Private subnets
# ---------------------------------------------------------------------------

resource "aws_subnet" "private" {
  count = 2

  vpc_id            = aws_vpc.dify.id
  cidr_block        = var.private_subnet_cidrs[count.index]
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = { Name = "dify-private-${count.index + 1}" }
}

# ---------------------------------------------------------------------------
# NAT Gateway (single, in the first public subnet – sufficient for dev/prod;
# add a second one in public[1] for full AZ-redundant HA if needed)
# ---------------------------------------------------------------------------

resource "aws_eip" "nat" {
  domain = "vpc"

  tags = { Name = "dify-nat-eip" }

  depends_on = [aws_internet_gateway.dify]
}

resource "aws_nat_gateway" "dify" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public[0].id

  tags = { Name = "dify-nat" }

  depends_on = [aws_internet_gateway.dify]
}

# ---------------------------------------------------------------------------
# Route tables
# ---------------------------------------------------------------------------

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.dify.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.dify.id
  }

  tags = { Name = "dify-public-rt" }
}

resource "aws_route_table_association" "public" {
  count = 2

  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.dify.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.dify.id
  }

  tags = { Name = "dify-private-rt" }
}

resource "aws_route_table_association" "private" {
  count = 2

  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

# ---------------------------------------------------------------------------
# Locals – consumed by main.tf in place of the former input variables
# ---------------------------------------------------------------------------

locals {
  vpc_id             = aws_vpc.dify.id
  public_subnet_ids  = aws_subnet.public[*].id
  private_subnet_ids = aws_subnet.private[*].id
}
