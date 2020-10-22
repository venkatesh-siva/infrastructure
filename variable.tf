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
	description = "Region for VPC"
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