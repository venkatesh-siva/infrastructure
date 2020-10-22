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

ingress{
description = "Allow inbound HTTP traffic"
from_port = "80"
to_port = "80"
protocol = "tcp"
cidr_blocks = [var.routeTable_cidr]
}
ingress{
description = "Allow inbound SSH traffic"
from_port = "22"
to_port = "22"
protocol = "tcp"
cidr_blocks = [var.routeTable_cidr]
}
ingress{
description = "Allow inbound HTTPS traffic"
from_port = "443"
to_port = "443"
protocol = "tcp"
cidr_blocks = [var.routeTable_cidr]
}
ingress{
description = "Allow traffic to application port"
from_port = "8080"
to_port = "8080"
protocol = "tcp"
cidr_blocks = [var.routeTable_cidr]
}
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
cidr_blocks = [var.subnet1_cidr]
}
egress {
  from_port   = 0
  to_port     = 0
  protocol    = "-1"
  cidr_blocks  = [var.subnet1_cidr]
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
  parameter_group_name = "default.mysql5.7"
  publicly_accessible  = false
  db_subnet_group_name = aws_db_subnet_group.db_subnet_group.name
  vpc_security_group_ids = [aws_security_group.db_security_group.id]
  multi_az = false
  skip_final_snapshot = true
  tags = {
    Name = "MySQL Database Server"
  }
}
resource "aws_instance" "appserver" {
  ami                                  = var.ami_id
  instance_type                        = var.ec2_instance_type
  disable_api_termination              = false
  instance_initiated_shutdown_behavior = var.terminate
  vpc_security_group_ids               = [aws_security_group.app_security_group.id]
  subnet_id                            = "${aws_subnet.subnet1.id}"
  iam_instance_profile = aws_iam_instance_profile.ec2_s3_profile.name
  depends_on = [aws_db_instance.database_server]
  key_name = var.keyname
  root_block_device {
    volume_type = "gp2"
    volume_size = 20
    delete_on_termination = true
  }
   user_data     = <<-EOF
 #!/bin/bash
 sudo echo export "S3_BUCKET_NAME=${aws_s3_bucket.bucket.bucket}" >> /etc/environment
 sudo echo export "DB_ENDPOINT=${aws_db_instance.database_server.endpoint}" >> /etc/environment
 sudo echo export "DB_NAME=${aws_db_instance.database_server.name}" >> /etc/environment
 sudo echo export "DB_USERNAME=${aws_db_instance.database_server.username}" >> /etc/environment
 sudo echo export "DB_PASSWORD=${aws_db_instance.database_server.password}" >> /etc/environment
 sudo echo export "AWS_REGION=${var.aws_region}" >> /etc/environment
 sudo echo export "AWS_PROFILE=${var.profile}" >> /etc/environment
 EOF
  tags = {
    Name = "App Server"
  }
}

resource "aws_dynamodb_table_item" "dynamo_db_item" {
  table_name = aws_dynamodb_table.dynamodb_table.name
  hash_key   = aws_dynamodb_table.dynamodb_table.hash_key

  item = <<ITEM
{
  "id": {"S": "something"}
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

resource "aws_iam_instance_profile" "ec2_s3_profile" {
  name = var.ec2InstanceProfile
  role = aws_iam_role.ec2role.name
}
