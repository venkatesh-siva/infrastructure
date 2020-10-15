variable "access_key_id" {
     default = ""
}
variable "secret_key_id" {
     default = ""
}

variable "aws_vpcname"{
}

variable "aws_region" {
	default = "us-east-1"
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

variable "availabilityZone1" {
     default = "us-east-1a"
}
variable "availabilityZone2" {
     default = "us-east-1b"
}
variable "availabilityZone3" {
     default = "us-east-1c"
}

variable "profile" {
  description = "AWS profile name for CLI"
}