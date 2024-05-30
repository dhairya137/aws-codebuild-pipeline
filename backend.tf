# backend.tf
terraform {
  backend "s3" {
    bucket = "codebuild-dp137"
    key    = "terraform/state"
    region = "us-east-2"
  }
}