data "aws_region" "current" {}

resource "aws_ecs_cluster" "ddec" {
  name = "ddec-cluster-${var.environment}"
}

resource "aws_iam_role" "ecs_task_execution_role" {
  name = "ecs_task_execution_role-${var.environment}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "ecs-tasks.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ecs_task_execution_role" {
  for_each = toset([
    "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy",
    "arn:aws:iam::aws:policy/SecretsManagerReadWrite",
    "arn:aws:iam::aws:policy/CloudWatchFullAccess",
    "arn:aws:iam::aws:policy/AmazonSSMFullAccess",
    "arn:aws:iam::324777464715:policy/EcsSecretFetcher"
  ])
  role = aws_iam_role.ecs_task_execution_role.name
  policy_arn = each.value
}


resource "aws_security_group" "ddec_node_sg" {
  name = "ddec-security-group-${var.environment}"
  vpc_id = var.vpc_id

  ingress {
    from_port = 0
    to_port = 0
    protocol = "ALL"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port = 0
    to_port = 0
    protocol = "ALL"
    cidr_blocks = ["0.0.0.0/0"]
  }
}


resource "aws_service_discovery_private_dns_namespace" "ddec-disc-ns" {
  name = "ddec.${var.environment}"
  vpc  = var.vpc_id
}

resource "aws_service_discovery_service" "ddec-party" {
  count = var.desired_count
  name  = "party-${count.index + 1}"

  dns_config {
    namespace_id = aws_service_discovery_private_dns_namespace.ddec-disc-ns.id

    dns_records {
      ttl  = 10
      type = "A"
    }
  }

  health_check_custom_config {
    failure_threshold = 1
  }
}

resource "aws_ecs_task_definition" "ddec_node_task" {
  count = var.desired_count
  family = "ddec-node-${count.index + 1}" # append a suffix to the name
  network_mode = "awsvpc"
  cpu = "256"
  memory = "512"
  requires_compatibilities = ["FARGATE"]
  execution_role_arn = aws_iam_role.ecs_task_execution_role.arn

  container_definitions = jsonencode([{
    name = "ddec-node"
    image = "${var.image}"
    repositoryCredentials = {
      credentialsParameter = "${var.repository_arn_aws_creds}"
    }
    portMappings = [{
      containerPort = 50000
      hostPort = 50000
      protocol = "tcp"
    }]
    environment = [{
      name = "DDEC_PROTOCOL_HOST_ADDRESS"
      value = "party-${tostring(count.index+1)}.ddec.${var.environment}"
    }, {
      name = "DDEC_PROTOCOL_HOST_PORT"
      value = "50000"
    }, {
      name = "DDEC_PROTOCOL_ID"
      value = "${tostring(count.index + 1)}"
    }]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group" = var.cloudwatch_log_group_name
        "awslogs-region" = data.aws_region.current.name
        "awslogs-stream-prefix" = "ecs"
      }
    }
    command = ["moby"]
  }])

}


resource "aws_ecs_service" "ddec" {
  name = "ddec-service-${var.environment}-${count.index + 1}"
  desired_count = 1
  cluster = aws_ecs_cluster.ddec.id
  task_definition = element(aws_ecs_task_definition.ddec_node_task.*.arn, count.index)
  count = var.desired_count
  force_new_deployment = true
  triggers = {
    redeployment = plantimestamp()
  }
  launch_type = "FARGATE"
  network_configuration {
    security_groups = [aws_security_group.ddec_node_sg.id]
    subnets = var.subnet_ids
  }
  service_registries {
    registry_arn = aws_service_discovery_service.ddec-party[count.index].arn
  }
}
