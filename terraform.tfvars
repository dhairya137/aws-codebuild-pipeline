name                           ="ec2-war-instance-new"
instance_type                  ="t2.medium"
associate_public_ip_address    = true
vpcname                        ="war-vpc-ec2"
security_group                  ="war-security_group"
vpc_cidr                       ="10.0.0.0/16"
region                         = "us-east-2"
domain_name                     = "ceqapp.com"
ami                             = "RHEL-8.9.0_HVM-20240327-x86_64-4-Hourly2-GP3"
# ssm_required = "true"

tags = {
    ApplicationName   = "AWS War"
    ProjectName       = "AWS War"
    Role              = "aws-war-ec2-pipeline"
    Name              = "aws-war-ec2new"
    Owner             = "dhairya@gmail.com"
  }



