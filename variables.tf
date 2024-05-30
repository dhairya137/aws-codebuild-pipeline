 variable "name" {
   description = "name"
   type        = any
   default     = null
 }

 variable "ssm_required" {
   description = "ssm_required"
   type        = any
   default     = null
 }

 variable "ami" {
   description = "name"
   type        = any
   default     = "Windows_Server-2022*"
 }


 variable "domain_name" {
   description = "domain_name"
   type        = any
   default     = "ceq.terraform.war"
 }

 variable "region" {
   description = "region"
   type        = any
   default     = null
 }
 variable "instance_type" {
   description = "instance_type"
   type        = any
   default     = null
 }

 variable "associate_public_ip_address" {
   description = "associate_public_ip_address"
   type        = any
   default     = null
 }

 variable "tags" {
   description = "(optional)"  
   type        = map(string)
   default     = null
 }

 variable "vpcname" {
   description = "vpcname"
   type        = any
   default     = null
 }

 variable "vpc_cidr" {
   description = "vpc_cidr"
   type        = any
   default     = null
 }

variable "security_group" {
   description = "security_group"
   type        = any
   default     = null
 }


