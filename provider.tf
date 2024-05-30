terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
      version = "5.48.0"
    }
  }
}

provider "aws" {
   region = var.region
   default_tags {
    tags = {
      ApplicationName   = "AWS War"
      ProjectName       = "AWS War"
      Role              = "aws-war-ec2-pipeline"
      Name              = "aws-war-ec2"
      Owner             = "gagan.arora@cloudeq.com"
    }
  }
}
