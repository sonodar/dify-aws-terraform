# dify-aws-terraform

Terraform template for Dify on AWS

## Premise and summary

- This template creates a dedicated VPC (and subnets, NAT gateway, route tables) for Dify in `vpc.tf`; no pre-existing VPC is required.
- The official Dify setup uses Squid as a Forward Proxy for SSRF protection, but it is omitted here.
- ElastiCache Redis cluster mode is disabled due to connection errors.
- PostgreSQL `pgvector` is used as the Vector Storage backend.
- Built with Aurora PostgreSQL Serverless, but a standard RDS instance can be used as well.

## Prerequisites

- Terraform

## Usage

1. Clone this repository
2. Edit `terraform.tfvars` to set your variables
3. Edit `backend.tf` to set your S3 bucket and DynamoDB table
4. Run `terraform init`
5. Run `terraform plan`
6. Run `terraform apply -target=aws_rds_cluster_instance.dify` (this creates the VPC and networking, then the RDS cluster and instance so you can run the SQL in step 7).
7. Execute the following SQL in the RDS cluster (use the same password as `dify_db_password` in your tfvars).

    **Run in the AWS Console (RDS Query Editor):**

    1. In the AWS Console, open **RDS** → **Query Editor**.
    2. Connect to your cluster:
       - **Database type:** PostgreSQL
       - **Authentication:** Database user name and password
       - **Database user name:** `postgres`
       - **Database password:** the value of `db_master_password` (from your tfvars or SSM)
       - **Database name:** leave as `postgres` (or select the cluster and let it choose the default).
    3. In the first query tab, run:

    ```sql
    CREATE ROLE dify WITH LOGIN PASSWORD 'your-dify-db-password';
    GRANT dify TO postgres;
    CREATE DATABASE dify WITH OWNER dify;
    ```

    4. In Query Editor, switch the connection (or open a new tab) to **Database name:** `dify`, same user `postgres`, then run:

    ```sql
    CREATE EXTENSION vector;
    ```

    (`\c dify` is a psql client command; in Query Editor you choose the database when connecting instead.)

8. Run `terraform apply`
9. Run `terraform apply` again, if task is not started

Once the deployment is complete and all ECS tasks are running, access the `dify_url` shown in the Terraform output.
