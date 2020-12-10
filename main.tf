provider "aws" {
	profile = "${var.profile}"
  access_key = "${var.access_key_id}"
  secret_key = "${var.secret_key_id}"
  region = "${var.aws_region}"
}

# VPC
resource "aws_vpc" "csye6225_vpc" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true
  enable_classiclink_dns_support = true
  assign_generated_ipv6_cidr_block = false

  tags = {
    Name = "${var.aws_vpcname}"
  }
}

# Internet Gateway
resource "aws_internet_gateway" "csye6225_gateway" {
  vpc_id = aws_vpc.csye6225_vpc.id
  tags = {
    Name = "${var.aws_vpcname}_Gateway"
  }
}

# Subnets 
resource "aws_subnet" "subnet1" {

  vpc_id = aws_vpc.csye6225_vpc.id
  cidr_block = var.subnet1_cidr
  availability_zone = "${var.aws_region}a"
  map_public_ip_on_launch = true
  tags = {
    Name = "${var.aws_vpcname}_Subnet1"
  }
}
resource "aws_subnet" "subnet2" {
  
  vpc_id = aws_vpc.csye6225_vpc.id
  cidr_block = var.subnet2_cidr
  availability_zone = "${var.aws_region}b"
  map_public_ip_on_launch = true
  tags ={
    Name = "${var.aws_vpcname}_Subnet2"
  }
}
resource "aws_subnet" "subnet3" {
  
  vpc_id = "${aws_vpc.csye6225_vpc.id}"
  cidr_block = "${var.subnet3_cidr}"
  availability_zone = "${var.aws_region}c"
  map_public_ip_on_launch = true
  tags ={
    Name = "${var.aws_vpcname}_Subnet3"
  }
}
# Route table
resource "aws_route_table" "route_table" {
  vpc_id = aws_vpc.csye6225_vpc.id
  route {
    cidr_block = var.routeTable_cidr
    gateway_id = aws_internet_gateway.csye6225_gateway.id
  }
  
  tags ={
    Name = "${var.aws_vpcname}_RouteTable"
  }
}

# Route table association with subnets
resource "aws_route_table_association" "route_subnet1" {
  subnet_id      = aws_subnet.subnet1.id
  route_table_id = aws_route_table.route_table.id
}

resource "aws_route_table_association" "route_subnet2" {
  subnet_id      = aws_subnet.subnet2.id
  route_table_id = aws_route_table.route_table.id
}

resource "aws_route_table_association" "route_subnet3" {
  subnet_id      = aws_subnet.subnet3.id
  route_table_id = aws_route_table.route_table.id
}

resource "aws_security_group" "app_security_group"{
name = "application security group"
description = "Open ports 22, 80, 443 and 8080"
vpc_id = aws_vpc.csye6225_vpc.id

#ingress{
#description = "Allow inbound HTTP traffic"
#from_port = "80"
#to_port = "80"
#protocol = "tcp"
#cidr_blocks = [var.routeTable_cidr]
#}
ingress{
description = "Allow inbound SSH traffic"
from_port = "22"
to_port = "22"
protocol = "tcp"
cidr_blocks = [var.routeTable_cidr]
}
#ingress{
#description = "Allow inbound HTTPS traffic"
#from_port = "443"
#to_port = "443"
#protocol = "tcp"
#cidr_blocks = [var.routeTable_cidr]
#}
#ingress{
#description = "Allow traffic to application port"
#from_port = "8080"
#to_port = "8080"
#protocol = "tcp"
#cidr_blocks = [var.routeTable_cidr]
#}
egress {
  from_port   = 0
  to_port     = 0
  protocol    = "-1"
  cidr_blocks  = ["0.0.0.0/0"]
  }
tags ={
Name = "application security group"
}
}
resource "aws_security_group" "db_security_group"{
name = "database security group"
description = "Open port 3306 for Database traffic"
vpc_id = aws_vpc.csye6225_vpc.id

ingress{
description = "Allow inbound Database traffic"
from_port = "3306"
to_port = "3306"
protocol = "tcp"
#cidr_blocks = [var.subnet1_cidr]
security_groups = [aws_security_group.app_security_group.id]
}
egress {
  from_port   = 0
  to_port     = 0
  protocol    = "-1"
  cidr_blocks  = [var.routeTable_cidr]
  }
tags ={
Name = "DB security group"
}
}


resource "aws_s3_bucket" "bucket" {
  bucket = var.bucketname
  acl = "private"
  force_destroy = true
  lifecycle_rule {
    enabled = true
    transition {
      days = 30
      storage_class = "STANDARD_IA"
    }
  }
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = var.encryption_algorithm
      }
    }
  }
}

resource "aws_db_subnet_group" "db_subnet_group" {
  name       = var.db_subnet_group
  subnet_ids = [aws_subnet.subnet1.id , aws_subnet.subnet2.id]

  tags = {
    Name = "DB Subnet Group "
  }
}

resource "aws_db_instance" "database_server" {
  allocated_storage    = 20
  storage_type         = "gp2"
  engine               = var.db_engine
  engine_version       = "5.7"
  instance_class       = var.db_instance_class
  identifier           = var.db_identifier
  name                 = var.dbname
  username             = var.db_username
  password             = var.db_password
  parameter_group_name = "${aws_db_parameter_group.rds.name}"
  publicly_accessible  = false
  db_subnet_group_name = aws_db_subnet_group.db_subnet_group.name
  vpc_security_group_ids = [aws_security_group.db_security_group.id]
  multi_az = false
  skip_final_snapshot = true
  storage_encrypted = true
  tags = {
    Name = "MySQL Database Server"
  }
}

resource "aws_db_parameter_group" "rds" {
 name = "rds-params"
 family = "mysql5.7"
 
 parameter {
 name = "performance_schema"
 value = 1
 apply_method = "pending-reboot"
 }
}
#resource "aws_instance" "appserver" {
#  ami                                  = var.ami_id
#  instance_type                        = var.ec2_instance_type
#  disable_api_termination              = false
#  instance_initiated_shutdown_behavior = var.terminate
#  vpc_security_group_ids               = [aws_security_group.app_security_group.id]
#  subnet_id                            = "${aws_subnet.subnet1.id}"
#  iam_instance_profile = aws_iam_instance_profile.ec2_s3_profile.name
#  depends_on = [aws_db_instance.database_server]
#  key_name = var.keyname
#  root_block_device {
#    volume_type = "gp2"
#    volume_size = 20
#    delete_on_termination = true
#  }
#   user_data     = <<-EOF
# #!/bin/bash
# sudo echo export "S3_BUCKET_NAME=${aws_s3_bucket.bucket.bucket}" >> /etc/environment
# sudo echo export "DB_ENDPOINT=${aws_db_instance.database_server.endpoint}" >> /etc/environment
# sudo echo export "DB_NAME=${aws_db_instance.database_server.name}" >> /etc/environment
# sudo echo export "DB_USERNAME=${aws_db_instance.database_server.username}" >> /etc/environment
# sudo echo export "DB_PASSWORD=${aws_db_instance.database_server.password}" >> /etc/environment
# sudo echo export "AWS_REGION=${var.aws_region}" >> /etc/environment
# sudo echo export "AWS_PROFILE=${var.profile}" >> /etc/environment
# EOF
#  tags = {
#    Name = "App Server"
#  }
#}

resource "aws_dynamodb_table_item" "dynamo_db_item" {
  table_name = aws_dynamodb_table.dynamodb_table.name
  hash_key   = aws_dynamodb_table.dynamodb_table.hash_key

  item = <<ITEM
{
  "id": {"S": "test from terraform"}
}
ITEM
}
resource "aws_dynamodb_table" "dynamodb_table" {
  name           = var.dynamodb_name
  hash_key       = "id"
  read_capacity    = 5
  write_capacity   = 5
  attribute {
    name = "id"
    type = "S"
  }
}
# IAM POLICY
resource "aws_iam_policy" "WebAppS3" {
  name        = var.s3policyName
  description = "Policy for EC2 instance to use S3"
policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:*"
      ],
      "Resource": ["${aws_s3_bucket.bucket.arn}","${var.bucketARN}" ]
    }
  ]
}
EOF
}
# IAM ROLE
resource "aws_iam_role" "ec2role" {
  name = var.s3roleName
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
  {
    "Action": "sts:AssumeRole",
    "Principal": {
    "Service": "ec2.amazonaws.com"
    },
    "Effect": "Allow",
    "Sid": ""
  }
  ]
}
EOF
  tags = {
    Name = "Custom Access Policy for EC2-S3"
  }
}

resource "aws_iam_role_policy_attachment" "role_policy_attacher" {
  role       = aws_iam_role.ec2role.name
  policy_arn = aws_iam_policy.WebAppS3.arn
}

#resource "aws_iam_instance_profile" "ec2_s3_profile" {
#  name = var.ec2InstanceProfile
#  role = aws_iam_role.ec2role.name
#}

# This policy is required for EC2 instances to download latest application revision.
resource "aws_iam_policy" "CodeDeploy_EC2_S3" {
  name        = "${var.CodeDeploy-EC2-S3}"
  description = "Policy for EC2 instance to store and retrieve  artifacts in S3"
policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:Get*",
        "s3:List*"
      ],
      "Resource": [ "${var.codedeploy_bucket_arn}" , "${var.codedeploy_bucket_arn_star}" ]
    }
  ]
}
EOF
}
# Policy allows GitHub Actions to upload artifacts from latest successful build to dedicated S3 bucket used by CodeDeploy.
resource "aws_iam_policy" "GH_Upload_To_S3" {
  name        = "${var.GH-Upload-To-S3}"
  description = "Policy for Github actions script to store artifacts in S3"
policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:PutObject",
        "s3:Get*",
        "s3:List*"
      ],
      "Resource": [ "${var.codedeploy_bucket_arn}" , "${var.codedeploy_bucket_arn_star}" ]
    }
  ]
}
EOF
}


# policy allows GitHub Actions to call CodeDeploy APIs to initiate application deployment on EC2 instances.
resource "aws_iam_policy" "GH_Code_Deploy" {
  name        = "${var.GH-Code-Deploy}"
  description = "Policy allows GitHub Actions to call CodeDeploy APIs to initiate application deployment on EC2 instances."
policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "codedeploy:RegisterApplicationRevision",
        "codedeploy:GetApplicationRevision"
      ],
      "Resource": [
        "arn:aws:codedeploy:${var.aws_region}:${var.account_id}:application:${var.codedeploy_appname}"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "codedeploy:CreateDeployment",
        "codedeploy:GetDeployment"
      ],
      "Resource": [
        "*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "codedeploy:GetDeploymentConfig"
      ],
      "Resource": [
        "arn:aws:codedeploy:${var.aws_region}:${var.account_id}:deploymentconfig:CodeDeployDefault.OneAtATime",
        "arn:aws:codedeploy:${var.aws_region}:${var.account_id}:deploymentconfig:CodeDeployDefault.HalfAtATime",
        "arn:aws:codedeploy:${var.aws_region}:${var.account_id}:deploymentconfig:CodeDeployDefault.AllAtOnce"
      ]
    }
  ]
}
EOF
}

#attach policies to ghactions user

#attaching CodeDeploy_EC2_S3 policy to ghactions  user
resource "aws_iam_user_policy_attachment" "attach_GH_Upload_To_S3" {
  user       = var.ghactions_username
  policy_arn = aws_iam_policy.GH_Upload_To_S3.arn
}

#attaching GH_Code_Deploy policy to ghactions  user
resource "aws_iam_user_policy_attachment" "attach_GH_Code_Deploy" {
  user       = var.ghactions_username
  policy_arn = aws_iam_policy.GH_Code_Deploy.arn
}

# create Role for Code Deploy
resource "aws_iam_role" "CodeDeployEC2ServiceRole" {
  name = var.CodeDeployEC2ServiceRole
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
  {
    "Action": "sts:AssumeRole",
    "Principal": {
    "Service": "ec2.amazonaws.com"
    },
    "Effect": "Allow",
    "Sid": ""
  }
  ]
}
EOF
  tags = {
    Name = "CodeDeployEC2ServiceRole access policy"
  }
}

#create CodeDeployServiceRole role
resource "aws_iam_role" "CodeDeployServiceRole" {
  name = var.CodeDeployServiceRole
  # policy below has to be edited
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Service": "codedeploy.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
  tags = {
    Name = "CodeDeployEC2Role access policy"
  }
}

#Policy to be attached with CodeDeployServiceRole role
resource "aws_iam_role_policy_attachment" "CodeDeployEC2ServiceRole_webapps3_policy_attacher" {
  role       = aws_iam_role.CodeDeployEC2ServiceRole.name
  policy_arn = aws_iam_policy.WebAppS3.arn
}

resource "aws_iam_instance_profile" "ec2_s3_profile" {
  name = var.ec2InstanceProfile
  role = aws_iam_role.CodeDeployEC2ServiceRole.name
}

#Policy to be attached with CodeDeployServiceRole role
resource "aws_iam_role_policy_attachment" "CodeDeployServiceRole_policy_attacher" {
  role       = aws_iam_role.CodeDeployServiceRole.name
  policy_arn = var.CodeDeployServiceRole_policy
}



#attach policies to codedeploy role
resource "aws_iam_role_policy_attachment" "CodeDeployEC2ServiceRole_policy_attacher" {
  role       = aws_iam_role.CodeDeployEC2ServiceRole.name
  policy_arn = aws_iam_policy.CodeDeploy_EC2_S3.arn
}

# Code Deploy Applicaiton 
resource "aws_codedeploy_app" "codedeploy_app" {
  compute_platform = "Server"
  name             = var.codedeploy_appname
}

#  CodeDeploy Deployment Group
resource "aws_codedeploy_deployment_group" "example" {
  app_name              = aws_codedeploy_app.codedeploy_app.name
  deployment_group_name = var.codedeploy_group
  service_role_arn      = aws_iam_role.CodeDeployServiceRole.arn
  deployment_config_name = "CodeDeployDefault.AllAtOnce"
  deployment_style {
    deployment_option = "WITHOUT_TRAFFIC_CONTROL"
    deployment_type   = "IN_PLACE"
  }
  auto_rollback_configuration {
    enabled = true
    events  = ["DEPLOYMENT_FAILURE"]
  }
  autoscaling_groups = [aws_autoscaling_group.asg.name]
  load_balancer_info {
    target_group_info {
      name = "${aws_lb_target_group.lb-target-group.name}"
    }
  }
  ec2_tag_set {
    ec2_tag_filter {
      key   = "Name"
      type  = "KEY_AND_VALUE"
      value = "App Server"
    }
  }
}

#resource "aws_route53_record" "record" {
#  zone_id = var.zoneId
#  name    = var.record_name
#  type    = "A"
#  ttl     = "300"
#  records = [aws_instance.appserver.public_ip]
#}

resource "aws_iam_role_policy_attachment" "ec2-cloudwatch-attach" {
 role = "${aws_iam_role.CodeDeployEC2ServiceRole.name}"
 policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

// Creating launch configuration
resource "aws_launch_configuration" "asg_launch_config" {
  name = "asg_launch_config"
  image_id      = "${var.ami_id}"
  instance_type = "t2.micro"
  key_name = "${var.keyname}"
  associate_public_ip_address = true
  user_data = <<-EOF
 #!/bin/bash
 sudo echo export "S3_BUCKET_NAME=${aws_s3_bucket.bucket.bucket}" >> /etc/environment
 sudo echo export "DB_ENDPOINT=${aws_db_instance.database_server.endpoint}" >> /etc/environment
 sudo echo export "DB_NAME=${aws_db_instance.database_server.name}" >> /etc/environment
 sudo echo export "DB_USERNAME=${aws_db_instance.database_server.username}" >> /etc/environment
 sudo echo export "DB_PASSWORD=${aws_db_instance.database_server.password}" >> /etc/environment
 sudo echo export "AWS_REGION=${var.aws_region}" >> /etc/environment
 sudo echo export "AWS_PROFILE=${var.profile}" >> /etc/environment
 EOF
  iam_instance_profile = aws_iam_instance_profile.ec2_s3_profile.name
  security_groups = ["${aws_security_group.app_security_group.id}"]
   root_block_device {
    volume_type = "gp2"
    volume_size = 20
    delete_on_termination = true
  }

  lifecycle {
    create_before_destroy = true
  }
}

// Auto scaling group for EC2
resource "aws_autoscaling_group" "asg" {
  name                 = "asg"
  launch_configuration = "${aws_launch_configuration.asg_launch_config.name}"
  default_cooldown     = 60
  min_size             = 3
  max_size             = 5
  desired_capacity     = 3
  vpc_zone_identifier  = ["${aws_subnet.subnet1.id}","${aws_subnet.subnet2.id}", "${aws_subnet.subnet3.id}"]
  target_group_arns    = ["${aws_lb_target_group.lb-target-group.arn}"]

  lifecycle {
    create_before_destroy = true
  }
  tag {
    key                 = "Name"
    value               = "App Server"
    propagate_at_launch = true
  }
}

# AUTOSCALING POLICIES for EC2 autoscaling group

# Scale up policy 
resource "aws_autoscaling_policy" "WebServerScaleUpPolicy" {
  name                   = "WebServerScaleUpPolicy"
  scaling_adjustment     = 1
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 60
  autoscaling_group_name = "${aws_autoscaling_group.asg.name}"
}

# Scale down policy
resource "aws_autoscaling_policy" "WebServerScaleDownPolicy" {
  name                   = "WebServerScaleDownPolicy"
  scaling_adjustment     = -1
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 60
  autoscaling_group_name = "${aws_autoscaling_group.asg.name}"
}

# Scale up when average CPU usage is above 5%. Increment by 1.
resource "aws_cloudwatch_metric_alarm" "CPUAlarmHigh" {
  alarm_name          = "CPUAlarmHigh"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "300"
  statistic           = "Average"
  threshold           = "05"

  dimensions = {
    AutoScalingGroupName = "${aws_autoscaling_group.asg.name}"
  }

  alarm_description = "Scale-up if CPU > 5% for 2 minutes"
  alarm_actions     = ["${aws_autoscaling_policy.WebServerScaleUpPolicy.arn}"]
}

# Scale down when average CPU usage is below 3%. Decrement by 1
resource "aws_cloudwatch_metric_alarm" "CPUAlarmLow" {
  alarm_name          = "CPUAlarmLow"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "300"
  statistic           = "Average"
  threshold           = "03"

  dimensions = {
    AutoScalingGroupName = "${aws_autoscaling_group.asg.name}"
  }

  alarm_description = "Scale-down if CPU < 3% for 2 minutes"
  alarm_actions     = ["${aws_autoscaling_policy.WebServerScaleDownPolicy.arn}"]
}

# Application Load Balancer For Your Web Application
resource "aws_lb" "webapp-lb" {
  name               = "webapp-lb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = ["${aws_security_group.lbSecurityGroup.id}"]
  ip_address_type    = "ipv4"
  enable_deletion_protection = false
  subnets = ["${aws_subnet.subnet1.id}","${aws_subnet.subnet2.id}","${aws_subnet.subnet3.id}"]
  tags = {
    Environment = "production"
  }

}

resource "aws_lb_target_group" "lb-target-group" {
  health_check {
    interval            = 10
    path                = "/"
    protocol            = "HTTP"
    timeout             = 5
    healthy_threshold   = 5
    unhealthy_threshold = 2
  }
  name        = "lb-target-group"
  port        = 8080
  protocol    = "HTTP"
  target_type = "instance"
  vpc_id      = "${aws_vpc.csye6225_vpc.id}"
}

#  Application load balancer to accept HTTP traffic on port 80 and forward it to your application instances on whatever port it listens on.
resource "aws_lb_listener" "webapp-lb-listener" {
  load_balancer_arn = "${aws_lb.webapp-lb.arn}"
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

resource "aws_route53_record" "lbAlias" {
  zone_id = var.zoneId
  name    = var.record_name
  type    = "A"

  alias {
    name                   = "${aws_lb.webapp-lb.dns_name}"
    zone_id                = "${aws_lb.webapp-lb.zone_id}"
    evaluate_target_health = false
  }
}

resource "aws_security_group" "lbSecurityGroup" {
  name        = "lbSecurityGroup"
  description = "Allow TLS inbound traffic"
  vpc_id      = "${aws_vpc.csye6225_vpc.id}"

  ingress{
  description = "Allow inbound HTTPS traffic"
  from_port = "443"
  to_port = "443"
  protocol = "tcp"
  cidr_blocks = [var.routeTable_cidr]
  }

  ingress{
  description = "Allow inbound HTTP traffic"
  from_port = "80"
  to_port = "80"
  protocol = "tcp"
  cidr_blocks = [var.routeTable_cidr]
  }
  ingress{
  description = "Allow inbound HTTP traffic"
  from_port = "22"
  to_port = "22"
  protocol = "tcp"
  cidr_blocks = [var.routeTable_cidr]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags ={
    Name = "application security group"
  }
}

resource "aws_security_group_rule" "applicationSecurityGroupRule" {
  type              = "ingress"
  from_port         = 8080
  to_port           = 8080
  protocol          = "tcp"
  security_group_id = "${aws_security_group.app_security_group.id}"
  # cidr_blocks = ["0.0.0.0/0"]
  source_security_group_id = "${aws_security_group.lbSecurityGroup.id}"
} 

// Create SNS topic
resource "aws_sns_topic" "sns_topic" {
  name = "email-customer"
}

resource "aws_sns_topic_subscription" "subscribe_to_sns_topic" {
    topic_arn = "${aws_sns_topic.sns_topic.arn}"
    protocol  = "lambda"
    endpoint  = "${aws_lambda_function.emailOnSNS.arn}"
}

// Create IAM role for  lambda function
resource "aws_iam_role" "iamRoleForlambda" {
  name = "iamRoleForlambda"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role_policy.json
}

#assume_role_policy JSON data for Lambda Functions 
data "aws_iam_policy_document" "lambda_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

# Create Lambda function
resource "aws_lambda_function" "emailOnSNS" {
  role          = "${aws_iam_role.iamRoleForlambda.arn}"
  s3_bucket     = "codedeploy.prod.venkateshcsye6225.me"
  s3_key        = "lambda-0.0.1-SNAPSHOT.jar"    
  function_name    = "emailOnSNS"
  runtime          = "${var.lambda_runtime}"
  handler          = "${var.lambda_function_handler}"
  memory_size      = 2400
  timeout          = 120
  environment {
    variables = {
      SendersEmail = var.SendersEmail
    }
  }
}

resource "aws_iam_role_policy_attachment" "SNSAccessToEC2Role" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonSNSFullAccess"
  role = "${aws_iam_role.CodeDeployEC2ServiceRole.name}"
}

resource "aws_iam_role_policy_attachment" "DynamoDbAccessToLambdaFunctionRole" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess"
  role = "${aws_iam_role.iamRoleForlambda.name}"
}

resource "aws_iam_role_policy_attachment" "S3AccessToLambdaFunctionRole" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
  role = "${aws_iam_role.iamRoleForlambda.name}"
}

resource "aws_iam_role_policy_attachment" "SESAccessToLambdaFunctionRole" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonSESFullAccess"
  role = "${aws_iam_role.iamRoleForlambda.name}"
}

resource "aws_iam_role_policy_attachment" "SNSAccessToLambdaFunctionRole" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonSNSFullAccess"
  role = "${aws_iam_role.iamRoleForlambda.name}"
}

resource "aws_iam_role_policy_attachment" "BasicExecutionAccessToLambdaFunctionRole" {
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
  role = "${aws_iam_role.iamRoleForlambda.name}"
}

#IAM Policy for Lambda to allow SNS event to trigger it
resource "aws_iam_policy" "lambda_sns_policy" {
 name = "lambda_sns_policy"
 
 policy = <<-EOF
{
 "Statement":[
 {"Condition":
 {"ArnLike":{"AWS:SourceArn":"${aws_sns_topic.sns_topic.arn}"}},
 "Resource":"${aws_lambda_function.emailOnSNS.arn}",
 "Action":"lambda:invokeFunction",
 "Sid":"",
 "Effect":"Allow"
 }],
 "Id":"default",
 "Version":"2012-10-17"
}
 EOF
}


 
#Policy to be attached with Lambda role
resource "aws_iam_role_policy_attachment" "lambda_snsinvokepolicy_attacher" {
 role = aws_iam_role.iamRoleForlambda.name
 policy_arn = aws_iam_policy.lambda_sns_policy.arn
}

resource "aws_iam_policy" "ghaction-lambda-update-policy" {
  name        = "ghaction-lambda-update-policy"
  description = "Allows cicd user to access lambda function"

   policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "cloudformation:DescribeChangeSet",
                "cloudformation:DescribeStackResources",
                "cloudformation:DescribeStacks",
                "cloudformation:GetTemplate",
                "cloudformation:ListStackResources",
                "cloudwatch:*",
                "cognito-identity:ListIdentityPools",
                "cognito-sync:GetCognitoEvents",
                "cognito-sync:SetCognitoEvents",
                "dynamodb:*",
                "ec2:DescribeSecurityGroups",
                "ec2:DescribeSubnets",
                "ec2:DescribeVpcs",
                "events:*",
                "iam:GetPolicy",
                "iam:GetPolicyVersion",
                "iam:GetRole",
                "iam:GetRolePolicy",
                "iam:ListAttachedRolePolicies",
                "iam:ListRolePolicies",
                "iam:ListRoles",
                "iam:PassRole",
                "iot:AttachPrincipalPolicy",
                "iot:AttachThingPrincipal",
                "iot:CreateKeysAndCertificate",
                "iot:CreatePolicy",
                "iot:CreateThing",
                "iot:CreateTopicRule",
                "iot:DescribeEndpoint",
                "iot:GetTopicRule",
                "iot:ListPolicies",
                "iot:ListThings",
                "iot:ListTopicRules",
                "iot:ReplaceTopicRule",
                "kinesis:DescribeStream",
                "kinesis:ListStreams",
                "kinesis:PutRecord",
                "kms:ListAliases",
                "lambda:*",
                "logs:*",
                "s3:*",
                "sns:ListSubscriptions",
                "sns:ListSubscriptionsByTopic",
                "sns:ListTopics",
                "sns:Publish",
                "sns:Subscribe",
                "sns:Unsubscribe",
                "sqs:ListQueues",
                "sqs:SendMessage",
                "tag:GetResources",
                "xray:PutTelemetryRecords",
                "xray:PutTraceSegments"
            ],
            "Resource": "*"
        }
    ]
}
EOF
}
// Attaching ghaction-lamba-update-policy to cicd user
resource "aws_iam_user_policy_attachment" "ghaction-attach-lambda-update-Policy" {
  user       = var.ghactions_username
  policy_arn = "${aws_iam_policy.ghaction-lambda-update-policy.arn}"
}


resource "aws_lambda_permission" "allow_sns" {
  action        = "lambda:*"
  function_name = "${aws_lambda_function.emailOnSNS.function_name}"
  principal     = "sns.amazonaws.com"
  source_arn    = "arn:aws:sns:us-east-1:599351014538:email-customer"
}

# get certificate from Aws certificate manager
data "aws_acm_certificate" "certificate" {
  domain = var.record_name
 tags = {
 Name = "ImportedCert"
 }
}
 
resource "aws_lb_listener" "https_listner" {
  load_balancer_arn = aws_lb.webapp-lb.arn
  port = "443"
  protocol = "HTTPS"
  ssl_policy = "ELBSecurityPolicy-2016-08"
  certificate_arn = data.aws_acm_certificate.certificate.arn
  default_action {
    type = "forward"
    target_group_arn = aws_lb_target_group.lb-target-group.arn
  }
}