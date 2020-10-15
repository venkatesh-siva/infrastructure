provider "aws" {
  version = "~> 2.0"
  profile = "${var.profile}"
  access_key = "${var.access_key_id}"
  secret_key = "${var.secret_key_id}"
  region = "${var.aws_region}"
}

# Create a new VPC
resource "aws_vpc" "csye6225_a4_vpc" {
  cidr_block           = "${var.vpc_cidr}"
  enable_dns_hostnames = true
  enable_dns_support = true
  enable_classiclink_dns_support = true
  assign_generated_ipv6_cidr_block = false

  tags = {
    Name = "${var.aws_vpcname}"
  }
}

# Create Internet Gateway
resource "aws_internet_gateway" "csye6225_a4_Gateway" {
 vpc_id = "${aws_vpc.csye6225_a4_vpc.id}"
 tags = {
        Name = "${var.aws_vpcname}_Gateway"
  }
}

# create a new Subnet
resource "aws_subnet" "csye6225_a4_Subnet1" {
  vpc_id                  = "${aws_vpc.csye6225_a4_vpc.id}"
  cidr_block              = "${var.subnet1_cidr}"
  availability_zone       = "${var.availabilityZone1}"
  map_public_ip_on_launch = true
  tags = {
   Name = "${var.aws_vpcname}_Subnet1"
  }
}

# create a new Subnet 2
resource "aws_subnet" "csye6225_a4_Subnet2" {
  vpc_id                  = "${aws_vpc.csye6225_a4_vpc.id}"
  cidr_block              = "${var.subnet2_cidr}"
  availability_zone       = "${var.availabilityZone2}"
  map_public_ip_on_launch = true
  tags = {
   Name = "${var.aws_vpcname}_Subnet2"
  }
}


# create a new Subnet 3
resource "aws_subnet" "csye6225_a4_Subnet3" {
  vpc_id                  = "${aws_vpc.csye6225_a4_vpc.id}"
  cidr_block              = "${var.subnet3_cidr}"
  availability_zone       = "${var.availabilityZone3}"
  map_public_ip_on_launch = true  
  tags = {
   Name = "${var.aws_vpcname}_Subnet3"
  }
}

# Create Route Table
resource "aws_route_table" "csye6225_a4_route_table" {
 vpc_id = "${aws_vpc.csye6225_a4_vpc.id}"
 route {
    cidr_block = "${var.routeTable_cidr}"
    gateway_id = "${aws_internet_gateway.csye6225_a4_Gateway.id}"
  }
  tags = {
   Name = "${var.aws_vpcname}_RouteTable"
  }
}

resource "aws_route_table_association" "csye6225_route_table_subnet1" {
  subnet_id      = "${aws_subnet.csye6225_a4_Subnet1.id}"
  route_table_id = "${aws_route_table.csye6225_a4_route_table.id}"
}

resource "aws_route_table_association" "csye6225_route_table_subnet2" {
  subnet_id      = "${aws_subnet.csye6225_a4_Subnet2.id}"
  route_table_id = "${aws_route_table.csye6225_a4_route_table.id}"
}

resource "aws_route_table_association" "csye6225_route_table_subnet3" {
  subnet_id      = "${aws_subnet.csye6225_a4_Subnet3.id}"
  route_table_id = "${aws_route_table.csye6225_a4_route_table.id}"
}
