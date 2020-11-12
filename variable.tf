variable "access_key_id" {
	default=""
}
variable "secret_key_id" {
	default=""
}
variable "vpc_cidr" {
	default = "10.0.0.0/16"
}
variable "subnet1_cidr" {
	default = "10.0.0.0/24"
}
variable "subnet2_cidr" {
	default = "10.0.1.0/24"
}
variable "subnet3_cidr" {
	default = "10.0.2.0/24"
}
variable "routeTable_cidr" {
	default = "0.0.0.0/0"
}
variable "profile" {
  description = "The AWS profile configured locally"
}
variable "aws_region" {
	description = "Provide the Region"
}
variable "aws_vpcname"{
	description = "Provide VPC Name"
}
variable "bucketname"{
	description="Provide s3 bucket name"
}
variable "db_instance_class"{
	description="Instance Class for the DB"
	default = "db.t3.micro"
}
variable "db_identifier"{
	description= "RDS instance name"
	default = "csye6225-f20"
}
variable "db_username"{
	description= "Master Username for the DB"
	default = "csye6225fall2020"
}
variable "db_password"{
	description= "Master Password for the DB"
}
variable "terminate"{
	default="terminate"
}
variable "dbname"{
	description= "DB name in RDS instance"
	default = "csye6225"
}
variable "db_subnet_group"{
	description = " subnet group ensures RDS instace is created in the same vpc"
	default = "db_subnet_group"
}
variable "ec2_instance_type"{
	description="Appserver Instance type"
	default = "t2.micro"
}
variable "db_engine"{
	default="mysql"
}
variable "encryption_algorithm"{
	default="AES256"
}
variable "keyname"{
	default="csye6225-aws-fall2020"
}
variable "ami_id"{
	description = "Provide the AMI ID"
}
variable "dynamodb_name"{
	description = "Dynamo DB table Name1"
	default="csye6225"
}
variable "s3policyName"{
	default = "WebAppS3"
}
variable "bucketARN"{
	default="arn:aws:s3:::webapp.venkateshkumar.sivakumar/*"
}
variable "s3roleName"{
	default="EC2-CSYE6225"
}
variable "ec2InstanceProfile"{
	default="ec2-s3-profile"
}
variable "CodeDeploy-EC2-S3"{
	default="CodeDeploy-EC2-S3"
}
variable "GH-Upload-To-S3"{
	default="GH-Upload-To-S3"
}

variable "ghactions_username"{
	default="ghactions"
}

variable "GH-Code-Deploy"{
	default= "GH-Code-Deploy"
}

variable "CodeDeployEC2ServiceRole"{
	default="CodeDeployEC2ServiceRole"
}

variable "CodeDeployServiceRole"{
	default="CodeDeployServiceRole"
}

variable "account_id"{
	description = "Provide account_id"
}

variable "CodeDeployServiceRole_policy"{
	default="arn:aws:iam::aws:policy/service-role/AWSCodeDeployRole"
}

variable "codedeploy_appname"{
	default="csye6225-webapp"
}

variable "codedeploy_group"{
	default="csye6225-webapp-deployment"
}

variable "zoneId"{
	description = "Provide hosted zone id"
}

variable "record_name"{
	description = "Enter Record Name ex: api.dev.venkateshcsye6225.me"
}
variable "codedeploy_bucket_arn"{
	description = "Enter Record Name ex: arn:aws:s3:::codedeploy.dev.venkateshcsye6225.me"
}
variable "codedeploy_bucket_arn_star"{
	description = "Enter Record Name ex: arn:aws:s3:::codedeploy.dev.venkateshcsye6225.me/*"
}	
variable "cloudwatch_policy_arn"{
 default = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}