data "aws_availability_zones" "available" {}


locals {
  azs      = slice(data.aws_availability_zones.available.names, 0, 3)
  region = var.region
  name   = var.name
  s3_bucket_name = var.name
  vpc_cidr = var.vpc_cidr
  current_identity = data.aws_caller_identity.current.arn
  tags = var.tags
  domain_name = var.domain_name
  ebs_block = module.ec2.root_block_device
  user_data_windows = file("./user_data_window.ps1")
  user_data_rhel    = file("./user_data_rhel.sh")
  user_data = strcontains(var.ami, "RHEL") ? local.user_data_rhel : local.user_data_windows
  

network_acls = {
  default_inbound = [
    {
      rule_number = 900
      rule_action = "allow"
      from_port   = 32768
      to_port     = 65535
      protocol    = "tcp"
      cidr_block  = var.vpc_cidr
    },
  ]
  default_outbound = [
    {
      rule_number = 900
      rule_action = "allow"
      from_port   = 32768
      to_port     = 65535
      protocol    = "tcp"
      cidr_block  = var.vpc_cidr
    },
  ]
  public_inbound = [
    {
      rule_number = 100
      rule_action = "allow"
      from_port   = 80
      to_port     = 80
      protocol    = "tcp"
      cidr_block  = "0.0.0.0/0"
    },
    {
      rule_number = 110
      rule_action = "allow"
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      cidr_block  = "0.0.0.0/0"
    }
  ]
  public_outbound = [
    {
      rule_number = 100
      rule_action = "allow"
      from_port   = 80
      to_port     = 80
      protocol    = "tcp"
      cidr_block  = "0.0.0.0/0"
    },
    {
      rule_number = 110
      rule_action = "allow"
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      cidr_block  = "0.0.0.0/0"
    }
  ]
private_inbound = [
    {
      rule_number = 100
      rule_action = "allow"
      from_port   = 80
      to_port     = 80
      protocol    = "tcp"
      cidr_block  = "0.0.0.0/0"
    },
    {
      rule_number = 110
      rule_action = "allow"
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      cidr_block  = "0.0.0.0/0"
    }
  ]
  private_outbound = [
    {
      rule_number = 100
      rule_action = "allow"
      from_port   = 80
      to_port     = 80
      protocol    = "tcp"
      cidr_block  = "0.0.0.0/0"
    },
    {
      rule_number = 110
      rule_action = "allow"
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      cidr_block  = "0.0.0.0/0"
    }
  ]
}
}

################################################################################
# EC2 Module
################################################################################

module "ec2" {
  source = "git::https://github.com/cloudeq-EMU-ORG/aws-war-ec2-template.git"

  name = var.name

  ami                         = data.aws_ami.hardened_ami.id
  instance_type               = var.instance_type   
  availability_zone           = element(local.azs, 0)
  subnet_id                   =  var.ssm_required == null ? element(module.vpc[0].private_subnets, 0) : element(module.vpc_ssm[0].intra_subnets, 0)
  vpc_security_group_ids      =  var.ssm_required == null ? [module.security_group[0].security_group_id] :  [module.security_group_ssm[0].security_group_id]
 # associate_public_ip_address = var. associate_public_ip_address
  user_data = local.user_data
    # Enable Hibernation
    hibernation = true
    enable_volume_tags = false	
    root_block_device = [
    {
      encrypted   = true
      volume_type = "gp3"
      throughput  = 200
      volume_size = 50
      kms_key_id  = module.kms_complete.key_id
      tags = var.tags
    },
  ]
  monitoring = true
 create_iam_instance_profile = true
  iam_role_description        = "IAM role for EC2 instance"
  iam_role_policies = {
    AdministratorAccess = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"

}

    metadata_options = {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 2
    instance_metadata_tags      = "enabled"
  }
   tags = var.tags
}

################################################################################
# Supporting Resources
################################################################################

module "vpc" {
  count = var.ssm_required == null ? 1 : 0
  source  = "git::https://github.com/cloudeq-EMU-ORG/aws-war-vpc-template.git"

   name             = var.vpcname
   cidr             = var.vpc_cidr
   azs             = local.azs
   private_subnets = [for k, v in local.azs : cidrsubnet(var.vpc_cidr, 4, k)]
#  public_subnets  = [for k, v in local.azs : cidrsubnet(var.vpc_cidr, 8, k + 48)]
#   intra_subnets =   [for k, v in local.azs : cidrsubnet(local.vpc_cidr, 8, k)]
   
   tags            = var.tags
   enable_flow_log           = true
   flow_log_destination_type = "s3"
   flow_log_destination_arn  = module.s3_bucket.s3_bucket_arn

   public_dedicated_network_acl   = true
   public_inbound_acl_rules       = concat(local.network_acls["default_inbound"], local.network_acls["public_inbound"])
   public_outbound_acl_rules      = concat(local.network_acls["default_outbound"], local.network_acls["public_outbound"])

  private_dedicated_network_acl  = true
  private_inbound_acl_rules      = concat(local.network_acls["default_inbound"], local.network_acls["private_inbound"])
  private_outbound_acl_rules     = concat(local.network_acls["default_outbound"], local.network_acls["private_outbound"])
	
 
  manage_default_network_acl = true

}

    data "aws_ami" "hardened_ami" {
    most_recent   = true
    owners        = ["self"]
	
     filter {
      name          = "name"
      values  = [var.ami]
  }
}

################################################################################
# Supporting Resources
################################################################################
data "aws_region" "current" {}
resource "random_pet" "this" {
  length = 2
}

module "kms_complete" {
  source = "git::https://github.com/cloudeq-EMU-ORG/aws-war-kms-template.git"

  description             = "Complete key example showing various configurations available"
  enable_key_rotation     = true
  is_enabled              = true
  key_usage               = "ENCRYPT_DECRYPT"
  multi_region            = false

  # Policy
  enable_default_policy                  = true
  key_owners                             = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
  key_administrators                     = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
  key_service_roles_for_autoscaling      = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"]
  key_statements = [
    {
      sid = "CloudWatchLogs"
      actions = [
        "kms:Encrypt*",
        "kms:Decrypt*",
        "kms:ReEncrypt*",
        "kms:GenerateDataKey*",
        "kms:Describe*"
      ]
      resources = ["*"]

      principals = [
        {
          type        = "Service"
          identifiers = ["logs.${data.aws_region.current.name}.amazonaws.com"]
        }
      ]

      conditions = [
        {
          test     = "ArnLike"
          variable = "kms:EncryptionContext:aws:logs:arn"
          values = [
            "arn:aws:logs:${local.region}:${data.aws_caller_identity.current.account_id}:log-group:*",
          ]
        }
      ]
    }
  ]

  # Aliases
  aliases = [local.name]

  # Grants
  grants = {
    lambda = {
      grantee_principal = aws_iam_role.lambda.arn
      operations        = ["Encrypt", "Decrypt", "GenerateDataKey"]
      constraints = {
        encryption_context_equals = {
          Department = "Finance"
        }
      }
    }
  }

  tags = local.tags
}

resource "aws_iam_role" "lambda" {
  name_prefix = local.name

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = "sts:AssumeRole"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
tags                    = var.tags
}
data "aws_caller_identity" "current" {}

# S3 Bucket

module "s3_bucket" {
  source  = "git::https://github.com/cloudeq-EMU-ORG/aws-war-s3-template.git"
  bucket        = local.s3_bucket_name
  policy        = data.aws_iam_policy_document.flow_log_s3.json
  force_destroy = true

  tags = local.tags
    # Note: Object Lock configuration can be enabled only on new buckets
  # https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_object_lock_configuration
  object_lock_enabled = true
  object_lock_configuration = {
    rule = {
      default_retention = {
        mode = "GOVERNANCE"
        days = 1
      }
    }
  }

server_side_encryption_configuration = {
    rule = {
      apply_server_side_encryption_by_default = {
        sse_algorithm = "aws:kms"
        kms_master_key_id = module.kms_complete.key_arn
      }
      bucket_key_enabled = true
    }
  }

  # Bucket policies
  attach_policy                            = true
  attach_deny_insecure_transport_policy    = true
  attach_require_latest_tls_policy         = true
  attach_deny_incorrect_encryption_headers = true
  attach_deny_unencrypted_object_uploads   = true

  # S3 bucket-level Public Access Block configuration (by default now AWS has made this default as true for S3 bucket-level block public access)
  # block_public_acls       = true
  # block_public_policy     = true
  # ignore_public_acls      = true
  # restrict_public_buckets = true

  # S3 Bucket Ownership Controls
  # https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_ownership_controls
  control_object_ownership = true
  object_ownership         = "BucketOwnerPreferred"

  expected_bucket_owner = data.aws_caller_identity.current.account_id

  acl = "private" # "acl" conflicts with "grant" and "owner"

  versioning = {
    status     = true
    mfa_delete = false
  }

}

data "aws_iam_policy_document" "flow_log_s3" {
  statement {
    sid = "AWSLogDeliveryWrite"

    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }

    actions = ["s3:PutObject"]

    resources = ["arn:aws:s3:::${local.s3_bucket_name}/AWSLogs/*"]
  }

  statement {
    sid = "AWSLogDeliveryAclCheck"

    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }

    actions = ["s3:GetBucketAcl"]

    resources = ["arn:aws:s3:::${local.s3_bucket_name}"]
  }
}
module "security_group" {
  count = var.ssm_required == null ? 1 : 0
  source                 = "git::https://github.com/cloudeq-EMU-ORG/aws-war-security-group-template.git"
  name                   = var.security_group
  description             = "Security group for example usage with EC2 instance"
  vpc_id                  = module.vpc[0].vpc_id
  egress_cidr_blocks      = ["10.1.0.0/16"]
 ingress_cidr_blocks      = ["10.1.0.0/16"]
  ingress_rules           = ["http-8080-tcp"]
  egress_rules            = ["http-8080-tcp"]
  egress_ipv6_cidr_blocks = null
  tags                    = var.tags
}


resource "aws_ebs_snapshot" "example_snapshot" {
  volume_id = local.ebs_block[0].volume_id 
  tags = var.tags
}



#########################################
#######   SSM Manager Resources     #####
#########################################


module "vpc_ssm" {
  count = var.ssm_required == null ? 0 : 1
  source  = "git::https://github.com/cloudeq-EMU-ORG/aws-war-vpc-template.git"

  name = local.name
  cidr = local.vpc_cidr

  azs           = local.azs
  intra_subnets = [for k, v in local.azs : cidrsubnet(local.vpc_cidr, 8, k)]

  tags = var.tags
}

module "security_group_ssm" {
  count = var.ssm_required == null ? 0 : 1
  source  = "git::https://github.com/cloudeq-EMU-ORG/aws-war-security-group-template.git"

  name        = "${local.name}-ec2"
  description = "Security Group for EC2 Instance Egress"

  vpc_id = module.vpc_ssm[0].vpc_id

  egress_rules = ["https-443-tcp"]

  tags = var.tags
}

module "vpc_endpoints_ssm" {
  count = var.ssm_required == null ? 0 : 1
  source  = "git::https://github.com/cloudeq-EMU-ORG/aws-war-vpc-template.git//modules/vpc-endpoints"

  vpc_id = module.vpc_ssm[0].vpc_id

  endpoints = { for service in toset(["ssm", "ssmmessages", "ec2messages"]) :
    replace(service, ".", "_") =>
    {
      service             = service
      subnet_ids          = module.vpc_ssm[0].intra_subnets
      private_dns_enabled = true
      tags                = { Name = "${local.name}-${service}" }
    }
  }

  create_security_group      = true
  security_group_name_prefix = "${local.name}-vpc-endpoints-"
  security_group_description = "VPC endpoint security group"
  security_group_rules = {
    ingress_https = {
      description = "HTTPS from subnets"
      cidr_blocks = module.vpc_ssm[0].intra_subnets_cidr_blocks
    }
  }

  tags = var.tags
}
