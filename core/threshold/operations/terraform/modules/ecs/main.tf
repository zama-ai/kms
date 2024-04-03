data "aws_region" "current" {}

resource "aws_ecs_cluster" "ddec" {
  name = "ddec-cluster-${var.environment}"
}

resource "aws_ecs_cluster_capacity_providers" "ddec_ecs_cluster_capacity_provider" {
  cluster_name = aws_ecs_cluster.ddec.name

  capacity_providers = [aws_ecs_capacity_provider.ddec_ecs_capacity_provider.name]

  default_capacity_provider_strategy {
    capacity_provider = aws_ecs_capacity_provider.ddec_ecs_capacity_provider.name
    weight            = 100
    base              = 1
  }

}

# Create an ECS capacity provider for the EC2 instances
resource "aws_ecs_capacity_provider" "ddec_ecs_capacity_provider" {
  name = "ddec-ecs-capacity-provider-${var.environment}"

  auto_scaling_group_provider {
    auto_scaling_group_arn         = aws_autoscaling_group.ddec_party_ecs_asg.arn

    managed_scaling {
      status                    = "ENABLED"
      target_capacity           = 4
      minimum_scaling_step_size = 1
      maximum_scaling_step_size = 1
    }
  }
}

resource "aws_iam_role" "ddec_party_ecs_role" {
  name = "ddec_party_ecs_role-${var.environment}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = ["ecs-tasks.amazonaws.com", "ec2.amazonaws.com", "ecs.amazonaws.com"]
      }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ddec_party_ecs_role_attach" {
  for_each = toset([
    "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy",
    "arn:aws:iam::aws:policy/SecretsManagerReadWrite",
    "arn:aws:iam::aws:policy/CloudWatchFullAccess",
    "arn:aws:iam::aws:policy/AmazonSSMFullAccess",
    "arn:aws:iam::324777464715:policy/EcsSecretFetcher",
    "arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role",
  ])
  role = aws_iam_role.ddec_party_ecs_role.name
  policy_arn = each.value
}

resource "aws_iam_instance_profile" "ddec_party_ecs_profile" {
  name = "ddec_party_ec2_profile"
  role = aws_iam_role.ddec_party_ecs_role.name
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


locals {
  cloud_config_config = <<-END
    #cloud-config
    ${jsonencode({
      write_files = [
        {
          path        = "/home/ec2-user/grafana/datasources.yaml"
          permissions = "0664"
          owner       = "root:root"
          encoding    = "b64"
          content     = filebase64("${path.module}/conf/grafana-datasources.yaml")
        },
        {
          path        = "/home/ec2-user/otel-collector/otel-collector.yaml"
          permissions = "0664"
          owner       = "root:root"
          encoding    = "b64"
          content     = filebase64("${path.module}/conf/otel-collector.yaml")
        },
        {
          path        = "/home/ec2-user/tempo/tempo.yaml"
          permissions = "0664"
          owner       = "root:root"
          encoding    = "b64"
          content     = filebase64("${path.module}/conf/tempo.yaml")
        },
        {
          path        = "/home/ec2-user/prometheus/prometheus.yaml"
          permissions = "0664"
          owner       = "root:root"
          encoding    = "b64"
          content     = filebase64("${path.module}/conf/prometheus.yaml")
        },
      ]
      packages = ["jq","mode_ssl", "htop", "git", "docker"]
      runcmd = [
        "mkdir -p /home/ec2-user/grafana",
        "mkdir -p /home/ec2-user/otel-collector",
        "mkdir -p /home/ec2-user/tempo/data",
        "mkdir -p /home/ec2-user/prometheus/data",
        "chown -R ec2-user:ec2-user /home/ec2-user"
      ]
    })}
  END
}

data "cloudinit_config" "init_files" {
  gzip          = true
  base64_encode = true

  part {
    content_type = "text/cloud-config"
    content      = local.cloud_config_config
  }

  part {
    content_type = "text/x-shellscript"
    filename     = "init.sh"
    content  = templatefile("${path.module}/conf/init.tftpl", {
      cluster-name = aws_ecs_cluster.ddec.name,
      region = data.aws_region.current.name,
      party-asg = "ddec-party-ecs-asg-${var.environment}"
    })
  }
}



resource "aws_launch_template" "ddec_ecs_launch_template" {
  name = "ddec-ecs-launch-template"

  image_id      = var.ami_ecs_optimized
  instance_type = "${var.instance_type}"

  iam_instance_profile {
    name = aws_iam_instance_profile.ddec_party_ecs_profile.name
  }

  lifecycle {
    create_before_destroy = true
  }

  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_size = 120
      volume_type = "gp2"
    }
  }

  network_interfaces {
    associate_public_ip_address = false
    security_groups            = [aws_security_group.ddec_node_sg.id]
  }

  user_data = data.cloudinit_config.init_files.rendered

  key_name = var.key_name

  tag_specifications {
    resource_type = "instance"

    tags = {
      Name        = "ddec-party-ecs-instance"
      Terraform   = "true"
      Environment = "dev"
    }
  }

}

# Create an auto-scaling group for the ECS instances
resource "aws_autoscaling_group" "ddec_party_ecs_asg" {
  name = "ddec-party-ecs-asg-${var.environment}"

  min_size         = 1
  max_size         = 4
  desired_capacity = 4
  force_delete     = true
  health_check_type = "EC2"
  health_check_grace_period = 300
  protect_from_scale_in = false

  launch_template {
    id      = aws_launch_template.ddec_ecs_launch_template.id
    version = aws_launch_template.ddec_ecs_launch_template.latest_version
  }

  lifecycle {
    create_before_destroy = true
  }

  vpc_zone_identifier = var.subnet_ids

  tag {
    key                 = "Name"
    value               = "ddec-party-ecs-instance-${var.environment}"
    propagate_at_launch = true
  }

  tag {
    key                 = "Terraform"
    value               = "true"
    propagate_at_launch = true
  }

  tag {
    key                 = "Environment"
    value               = "dev"
    propagate_at_launch = true
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
  memory = "1024"
  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }
  requires_compatibilities = ["EC2"]
  execution_role_arn = aws_iam_role.ddec_party_ecs_role.arn

  volume {
    name      = "otel-collector-config"
    host_path = "/home/ec2-user/otel-collector/otel-collector.yaml"
  }

  container_definitions = jsonencode([{
    name = "ddec-party-${count.index + 1}"
    image = "${var.image}"
    command = ["moby"]
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
    },
    {
      name = "DDEC_TRACING_SERVICE_NAME"
      value = "moby-party-${tostring(count.index + 1)}"
    },
    {
      name = "DDEC_TRACING_ENDPOINT"
      value = "http://localhost:4317"
    },
    {
      name = "RUN_MODE"
      value = "${var.environment}"
    },
    { name = "NO_COLOR"
      value = "true"
    }]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group" = var.cloudwatch_log_group_name
        "awslogs-region" = data.aws_region.current.name
        "awslogs-stream-prefix" = "ecs"
      }
    }
    healthCheck = {
      command = ["grpc-health-probe", "--addr=localhost:50000"]
      interval = 5
      retries = 5
      startPeriod = 60
      timeout = 5
    }
  },
  {
    name = "otel-collector-party-${count.index + 1}"
    image = "otel/opentelemetry-collector:0.86.0"
    mountPoints = [{
      sourceVolume = "otel-collector-config"
      containerPath = "/etc/otel-collector.yaml"
      readOnly = true
    }]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group" = var.cloudwatch_log_group_name
        "awslogs-region" = data.aws_region.current.name
        "awslogs-stream-prefix" = "ecs"
      }
    }
    command = ["--config=/etc/otel-collector.yaml"]
  }])

}


resource "aws_service_discovery_service" "ddec_observability" {
  count = 1
  name  = "observability"

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


resource "aws_ecs_service" "ddec" {
  name = "ddec-service-${var.environment}-${count.index + 1}"
  desired_count = 1
  cluster = aws_ecs_cluster.ddec.id
  task_definition = element(aws_ecs_task_definition.ddec_node_task.*.arn, count.index)
  count = var.desired_count
  force_new_deployment = true
  placement_constraints {
    type = "distinctInstance"
  }
  triggers = {
    redeployment = plantimestamp()
  }
  capacity_provider_strategy {
    capacity_provider = aws_ecs_capacity_provider.ddec_ecs_capacity_provider.name
    weight = 100
  }

  network_configuration {
    security_groups = [aws_security_group.ddec_node_sg.id]
    subnets = var.subnet_ids
  }
  service_registries {
    registry_arn = aws_service_discovery_service.ddec-party[count.index].arn
  }
  depends_on = [aws_autoscaling_group.ddec_party_ecs_asg]
}


resource "aws_ecs_task_definition" "ddec_observability_task" {
  count = 1
  family = "ddec-observability"
  network_mode = "awsvpc"
  memory = "512"
  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }
  requires_compatibilities = ["EC2"]
  execution_role_arn = aws_iam_role.ddec_party_ecs_role.arn


  volume {
    name      = "tempo-config"
    host_path = "/home/ec2-user/tempo/tempo.yaml"
  }

  volume {
    name      = "tempo-data"
    host_path = "/home/ec2-user/tempo/data"
  }

  volume {
    name      = "grafana-datasources"
    host_path = "/home/ec2-user/grafana/datasources.yaml"
  }

  volume {
    name      = "prometheus-data"
    host_path = "/home/ec2-user/prometheus/data"
  }

  volume {
    name      = "prometheus-config"
    host_path = "/home/ec2-user/prometheus/prometheus.yaml"
  }

  container_definitions = jsonencode([
    {
      name = "tempo"
      image = "grafana/tempo:latest"
      portMappings = [{
        containerPort = 14268
        hostPort = 14268
        protocol = "tcp"
      },
      {
        containerPort = 3200
        hostPort = 3200
        protocol = "tcp"
      },
      {
        containerPort = 4317
        hostPort = 4317
        protocol = "tcp"
      },
      {
        containerPort = 4318
        hostPort = 4318
        protocol = "tcp"
      },
      {
        containerPort = 9411
        hostPort = 9411
        protocol = "tcp"
      }]
      mountPoints = [{
        sourceVolume = "tempo-config"
        containerPath = "/etc/tempo.yaml"
        readOnly = true
      },
      {
        sourceVolume = "tempo-data"
        containerPath = "/tmp/tempo"
        readOnly = false
      }]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group" = var.cloudwatch_log_group_name
          "awslogs-region" = data.aws_region.current.name
          "awslogs-stream-prefix" = "ecs"
        }
      }
      command = ["-config.file=/etc/tempo.yaml"]
    },
    {
      name = "grafana"
      image = "grafana/grafana:10.1.1"
      mountPoints = [{
        sourceVolume = "grafana-datasources"
        containerPath = "/etc/grafana/provisioning/datasources/datasources.yaml"
        readOnly = true
      }]
      portMappings = [{
        containerPort = 3000
        hostPort = 3000
        protocol = "tcp"
      }]
      environment = [{
        name = "GF_AUTH_ANONYMOUS_ENABLED"
        value = "false"
      },
      { name = "GF_AUTH_DISABLE_LOGIN_FORM"
        value = "false"
      },
      { name = "GF_AUTH_DISABLE_SIGNOUT_MENU"
        value = "false"
      },
      { name = "GF_FEATURE_TOOGLE_ENABLED"
        value = "traceqlEditor"
      }]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group" = var.cloudwatch_log_group_name
          "awslogs-region" = data.aws_region.current.name
          "awslogs-stream-prefix" = "ecs"
        }
      }
      secrets = [{
        name = "GF_SECURITY_ADMIN_PASSWORD"
        valueFrom = "${var.grafana_secret_arn}:password::"
      },
      {
        name = "GF_SECURITY_ADMIN_USER"
        valueFrom = "${var.grafana_secret_arn}:username::"
      }]
    },
    {
      name = "prometheus"
      image = "prom/prometheus:latest"
      user = "root"
      command = [
        "--config.file=/etc/prometheus.yaml",
        "--storage.tsdb.path=/prometheus",
        "--web.enable-remote-write-receiver",
        "--enable-feature=exemplar-storage"
      ]
      mountPoints = [{
        sourceVolume = "prometheus-config"
        containerPath = "/etc/prometheus.yaml"
        readOnly = true
      },
      {
        sourceVolume = "prometheus-data"
        containerPath = "/prometheus"
        readOnly = false
      }]
      portMappings = [{
        containerPort = 9090
        hostPort = 9090
        protocol = "tcp"
      }]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group" = var.cloudwatch_log_group_name
          "awslogs-region" = data.aws_region.current.name
          "awslogs-stream-prefix" = "ecs"
        }
      }
    }
  ])

}


resource "aws_ecs_service" "ddec-observability" {
  name = "ddec-observability-service-${var.environment}"
  desired_count = 1
  cluster = aws_ecs_cluster.ddec.id
  task_definition = element(aws_ecs_task_definition.ddec_observability_task.*.arn, count.index)
  count = 1
  force_new_deployment = true
  placement_constraints {
    type       = "memberOf"
    expression = "attribute:ecs.availability-zone in [eu-west-3a, eu-west-3b, eu-west-3c]"
  }
  triggers = {
    redeployment = plantimestamp()
  }
  capacity_provider_strategy {
    capacity_provider = aws_ecs_capacity_provider.ddec_ecs_capacity_provider.name
    weight = 100
  }

  network_configuration {
    security_groups = [aws_security_group.ddec_node_sg.id]
    subnets = var.subnet_ids
  }
  depends_on = [aws_autoscaling_group.ddec_party_ecs_asg]

  service_registries {
    registry_arn = aws_service_discovery_service.ddec_observability[0].arn
  }

  load_balancer {
    target_group_arn = "${var.lb_target_group_arn}"
    container_name   = "grafana"
    container_port   = "3000"
  }

}
