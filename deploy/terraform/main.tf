# ---------------------------------------------------------------------------
# JIT Ephemeral Access Broker — Terraform deployment module
#
# Deploys the broker as an ECS Fargate service behind an ALB.
# One-command production deploy: terraform init && terraform apply
# ---------------------------------------------------------------------------
terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

variable "aws_region" {
  description = "AWS region for deployment"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Project name used for resource naming"
  type        = string
  default     = "jit-access-broker"
}

variable "image" {
  description = "Container image URI"
  type        = string
  default     = "ghcr.io/adhiman95/jit-access-broker:latest"
}

variable "vault_addr" {
  description = "HashiCorp Vault address"
  type        = string
}

variable "vault_token" {
  description = "Vault token (stored in Secrets Manager)"
  type        = string
  sensitive   = true
}

variable "pagerduty_api_token" {
  description = "PagerDuty API token"
  type        = string
  sensitive   = true
}

variable "jira_api_token" {
  description = "Jira API token"
  type        = string
  sensitive   = true
}

variable "jira_username" {
  description = "Jira username (email)"
  type        = string
}

variable "slack_signing_secret" {
  description = "Slack signing secret for slash commands"
  type        = string
  default     = ""
  sensitive   = true
}

variable "slack_bot_token" {
  description = "Slack bot token (xoxb-...)"
  type        = string
  default     = ""
  sensitive   = true
}

variable "container_port" {
  description = "Container listen port"
  type        = number
  default     = 8080
}

provider "aws" {
  region = var.aws_region
}

# --- Secrets Manager ---
resource "aws_secretsmanager_secret" "broker_config" {
  name        = "${var.project_name}/config"
  description = "Sensitive configuration for JIT Access Broker"
}

resource "aws_secretsmanager_secret_version" "broker_config" {
  secret_id = aws_secretsmanager_secret.broker_config.id
  secret_string = jsonencode({
    vault-addr           = var.vault_addr
    vault-token          = var.vault_token
    pagerduty-api-token  = var.pagerduty_api_token
    jira-api-token       = var.jira_api_token
    jira-username        = var.jira_username
    slack-signing-secret = var.slack_signing_secret
    slack-bot-token      = var.slack_bot_token
  })
}

# --- ECS Cluster ---
resource "aws_ecs_cluster" "broker" {
  name = var.project_name

  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

# --- CloudWatch Log Group ---
resource "aws_cloudwatch_log_group" "broker" {
  name              = "/ecs/${var.project_name}"
  retention_in_days = 30
}

# --- IAM Execution Role ---
data "aws_iam_policy_document" "task_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "task_execution" {
  name               = "${var.project_name}-execution"
  assume_role_policy = data.aws_iam_policy_document.task_assume.json
}

resource "aws_iam_role_policy_attachment" "task_execution" {
  role       = aws_iam_role.task_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# --- ECS Task Definition ---
resource "aws_ecs_task_definition" "broker" {
  family                   = var.project_name
  requires_compatibilities = ["FARGATE"]
  network_mode            = "awsvpc"
  cpu                     = "512"
  memory                  = "1024"
  execution_role_arn      = aws_iam_role.task_execution.arn

  container_definitions = jsonencode([
    {
      name  = "broker"
      image = var.image
      portMappings = [
        {
          containerPort = var.container_port
          hostPort      = var.container_port
          protocol      = "tcp"
        }
      ]
      secrets = [
        {
          name      = "VAULT_TOKEN"
          valueFrom = "${aws_secretsmanager_secret.broker_config.arn}:vault-token::"
        },
        {
          name      = "PAGERDUTY_API_TOKEN"
          valueFrom = "${aws_secretsmanager_secret.broker_config.arn}:pagerduty-api-token::"
        },
        {
          name      = "JIRA_API_TOKEN"
          valueFrom = "${aws_secretsmanager_secret.broker_config.arn}:jira-api-token::"
        },
        {
          name      = "SLACK_SIGNING_SECRET"
          valueFrom = "${aws_secretsmanager_secret.broker_config.arn}:slack-signing-secret::"
        },
        {
          name      = "SLACK_BOT_TOKEN"
          valueFrom = "${aws_secretsmanager_secret.broker_config.arn}:slack-bot-token::"
        }
      ]
      environment = [
        { name = "VAULT_ADDR", value = var.vault_addr },
        { name = "JIRA_USERNAME", value = var.jira_username }
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.broker.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "ecs"
        }
      }
    }
  ])
}

# --- ALB ---
resource "aws_lb" "broker" {
  name               = var.project_name
  internal           = false
  load_balancer_type = "application"
  subnets            = data.aws_subnets.default.ids
}

data "aws_subnets" "default" {
  filter {
    name   = "default-for-az"
    values = ["true"]
  }
}

resource "aws_lb_target_group" "broker" {
  name        = var.project_name
  port        = var.container_port
  protocol    = "HTTP"
  vpc_id      = data.aws_vpc.default.id
  target_type = "ip"

  health_check {
    path = "/healthz"
  }
}

data "aws_vpc" "default" {
  default = true
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.broker.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.broker.arn
  }
}

# --- ECS Service ---
resource "aws_ecs_service" "broker" {
  name            = var.project_name
  cluster         = aws_ecs_cluster.broker.id
  task_definition = aws_ecs_task_definition.broker.arn
  desired_count   = 2
  launch_type     = "FARGATE"

  load_balancer {
    target_group_arn = aws_lb_target_group.broker.arn
    container_name   = "broker"
    container_port   = var.container_port
  }

  network_configuration {
    subnets          = data.aws_subnets.default.ids
    assign_public_ip = true
  }
}

# --- Outputs ---
output "alb_dns_name" {
  value       = aws_lb.broker.dns_name
  description = "ALB DNS name — point your Slack slash command URL here"
}

output "health_check_url" {
  value       = "http://${aws_lb.broker.dns_name}/healthz"
  description = "Health check endpoint"
}

output "slack_command_url" {
  value       = "http://${aws_lb.broker.dns_name}/slack/command"
  description = "Mount this as your Slack slash command Request URL"
}

output "api_request_url" {
  value       = "http://${aws_lb.broker.dns_name}/api/v1/access/request"
  description = "Core API endpoint"
}