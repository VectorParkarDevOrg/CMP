#!/bin/bash

#############################################################################
# AWS EC2 Interactive Deployment Script with Terraform Backend
# Description: Interactive Bash script that generates and executes Terraform
# Author: Infrastructure Automation
# Version: 2.0 - FIXED AMI VALIDATION
#############################################################################

set -u
set -o pipefail

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Global variables
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/config.ini"
TF_DIR="${SCRIPT_DIR}/terraform_generated"

#############################################################################
# Utility Functions
#############################################################################

print_header() {
    echo -e "${CYAN}"
    echo "=============================================="
    echo "$1"
    echo "=============================================="
    echo -e "${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ ERROR: $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ WARNING: $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ INFO: $1${NC}"
}

error_exit() {
    print_error "$1"
    exit 1
}

validate_prerequisites() {
    print_info "Validating prerequisites..."

    if ! command -v aws &> /dev/null; then
        error_exit "AWS CLI is not installed. Please install it first."
    fi
    print_success "AWS CLI found"

    if ! command -v terraform &> /dev/null; then
        error_exit "Terraform is not installed. Please install it first."
    fi

    local tf_version=$(terraform version -json 2>/dev/null | grep -oP '"terraform_version":\s*"\K[^"]+' || terraform version | head -1 | awk '{print $2}')
    print_success "Terraform found: $tf_version"
}

#############################################################################
# Load AWS Credentials from Config File
#############################################################################

load_aws_credentials() {
    print_header "Loading AWS Credentials"

    if [ ! -f "$CONFIG_FILE" ]; then
        print_warning "Config file not found. Creating template..."
        cat > "$CONFIG_FILE" << 'EOF'
# AWS Configuration File
# DO NOT COMMIT THIS FILE TO VERSION CONTROL
# Add this file to .gitignore

[aws]
access_key = YOUR_AWS_ACCESS_KEY_HERE
secret_key = YOUR_AWS_SECRET_KEY_HERE
EOF
        print_error "Please edit $CONFIG_FILE with your AWS credentials and run the script again."
        exit 1
    fi

    # Parse config file
    AWS_ACCESS_KEY=$(grep -A 2 '\[aws\]' "$CONFIG_FILE" | grep 'access_key' | cut -d'=' -f2 | xargs)
    AWS_SECRET_KEY=$(grep -A 2 '\[aws\]' "$CONFIG_FILE" | grep 'secret_key' | cut -d'=' -f2 | xargs)

    if [ -z "$AWS_ACCESS_KEY" ] || [ "$AWS_ACCESS_KEY" == "YOUR_AWS_ACCESS_KEY_HERE" ]; then
        error_exit "Please set valid AWS credentials in $CONFIG_FILE"
    fi

    if [ -z "$AWS_SECRET_KEY" ] || [ "$AWS_SECRET_KEY" == "YOUR_AWS_SECRET_KEY_HERE" ]; then
        error_exit "Please set valid AWS credentials in $CONFIG_FILE"
    fi

    export AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY"
    export AWS_SECRET_ACCESS_KEY="$AWS_SECRET_KEY"
    export TF_VAR_aws_access_key="$AWS_ACCESS_KEY"
    export TF_VAR_aws_secret_key="$AWS_SECRET_KEY"

    # Validate credentials
    print_info "Validating AWS credentials..."
    local test_output
    test_output=$(aws sts get-caller-identity 2>&1)

    if [ $? -eq 0 ]; then
        print_success "AWS credentials validated successfully"
        ACCOUNT_ID=$(echo "$test_output" | grep -oP '"Account":\s*"\K[^"]+')
        print_info "AWS Account ID: $ACCOUNT_ID"
    else
        print_error "Failed to validate credentials from config file"
        echo "$test_output"
        exit 1
    fi
}

#############################################################################
# Interactive Selection Functions
#############################################################################

select_region() {
    print_header "AWS Region Selection"

    local regions=(
        "us-east-1"
        "us-east-2"
        "us-west-1"
        "us-west-2"
        "ap-south-1"
        "ap-northeast-1"
        "ap-northeast-2"
        "ap-southeast-1"
        "ap-southeast-2"
        "ca-central-1"
        "eu-central-1"
        "eu-west-1"
        "eu-west-2"
        "eu-west-3"
        "eu-north-1"
        "sa-east-1"
        "me-south-1"
        "af-south-1"
    )

    echo -e "${YELLOW}Select AWS Region:${NC}"
    PS3="Enter your choice (number): "

    select AWS_REGION in "${regions[@]}"; do
        if [[ -n "$AWS_REGION" ]]; then
            export AWS_DEFAULT_REGION="$AWS_REGION"
            export TF_VAR_aws_region="$AWS_REGION"
            print_success "Selected Region: $AWS_REGION"
            break
        fi
    done
}

select_os_type() {
    print_header "Operating System Selection"

    local os_types=(
        "amazon-linux-2023"
        "amazon-linux-2"
        "ubuntu-22.04"
        "ubuntu-20.04"
        "ubuntu-24.04"
        "debian-12"
        "debian-11"
        "rhel-9"
        "rhel-8"
        "windows-2022"
        "windows-2019"
        "suse-15"
    )

    local os_display=(
        "Amazon Linux 2023"
        "Amazon Linux 2"
        "Ubuntu 22.04 LTS"
        "Ubuntu 20.04 LTS"
        "Ubuntu 24.04 LTS"
        "Debian 12"
        "Debian 11"
        "Red Hat Enterprise Linux 9"
        "Red Hat Enterprise Linux 8"
        "Windows Server 2022"
        "Windows Server 2019"
        "SUSE Linux 15"
    )

    echo -e "${YELLOW}Select Operating System:${NC}"
    PS3="Enter your choice (number): "

    select choice in "${os_display[@]}"; do
        if [[ -n "$choice" ]]; then
            local index=$((REPLY - 1))
            OS_TYPE="${os_types[$index]}"
            export TF_VAR_os_type="$OS_TYPE"
            print_success "Selected OS: $choice"
            break
        fi
    done
}

select_architecture() {
    print_header "CPU Architecture Selection"

    local architectures=("x86_64" "arm64")

    echo -e "${YELLOW}Select CPU Architecture:${NC}"
    echo "1) x86_64 (Intel/AMD 64-bit)"
    echo "2) arm64 (AWS Graviton)"
    PS3="Enter your choice (number): "

    select ARCHITECTURE in "${architectures[@]}"; do
        if [[ -n "$ARCHITECTURE" ]]; then
            export TF_VAR_architecture="$ARCHITECTURE"
            print_success "Selected Architecture: $ARCHITECTURE"
            break
        fi
    done
}

#############################################################################
# Validate AMI Availability
#############################################################################

validate_ami_availability() {
    print_header "Validating AMI Availability"

    print_info "Checking if AMI exists for $OS_TYPE ($ARCHITECTURE) in $AWS_REGION..."

    local ami_name_pattern=""
    local ami_owner=""

    case "$OS_TYPE" in
        "amazon-linux-2023")
            ami_name_pattern="al2023-ami-*-kernel-*"
            ami_owner="amazon"
            ;;
        "amazon-linux-2")
            ami_name_pattern="amzn2-ami-hvm-*"
            ami_owner="amazon"
            ;;
        "ubuntu-22.04")
            ami_name_pattern="ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-*-server-*"
            ami_owner="099720109477"
            ;;
        "ubuntu-20.04")
            ami_name_pattern="ubuntu/images/hvm-ssd/ubuntu-focal-20.04-*-server-*"
            ami_owner="099720109477"
            ;;
        "ubuntu-24.04")
            ami_name_pattern="ubuntu/images/hvm-ssd/ubuntu-noble-24.04-*-server-*"
            ami_owner="099720109477"
            ;;
        "debian-12")
            ami_name_pattern="debian-12-*"
            ami_owner="136693071363"
            ;;
        "debian-11")
            ami_name_pattern="debian-11-*"
            ami_owner="136693071363"
            ;;
        "rhel-9")
            ami_name_pattern="RHEL-9*_HVM-*"
            ami_owner="309956199498"
            ;;
        "rhel-8")
            ami_name_pattern="RHEL-8*_HVM-*"
            ami_owner="309956199498"
            ;;
        "windows-2022")
            ami_name_pattern="Windows_Server-2022-English-Full-Base-*"
            ami_owner="amazon"
            ;;
        "windows-2019")
            ami_name_pattern="Windows_Server-2019-English-Full-Base-*"
            ami_owner="amazon"
            ;;
        "suse-15")
            ami_name_pattern="suse-sles-15-*"
            ami_owner="amazon"
            ;;
    esac

    # Try to find AMI
    local ami_output
    ami_output=$(aws ec2 describe-images \
        --owners "$ami_owner" \
        --filters "Name=name,Values=$ami_name_pattern" \
                  "Name=architecture,Values=$ARCHITECTURE" \
                  "Name=state,Values=available" \
                  "Name=root-device-type,Values=ebs" \
        --query 'Images | sort_by(@, &CreationDate) | [-1].ImageId' \
        --output text \
        --region "$AWS_REGION" 2>&1)

    if [ $? -ne 0 ]; then
        print_error "Failed to query AMIs from AWS"
        echo "$ami_output"
        exit 1
    fi

    VALIDATED_AMI_ID="$ami_output"

    if [ -z "$VALIDATED_AMI_ID" ] || [ "$VALIDATED_AMI_ID" == "None" ]; then
        print_error "No AMI found for the selected configuration!"
        echo ""
        echo "Configuration:"
        echo "  OS Type:       $OS_TYPE"
        echo "  Architecture:  $ARCHITECTURE"
        echo "  Region:        $AWS_REGION"
        echo ""
        print_info "Possible solutions:"
        echo "  1. Try a different architecture (x86_64 vs arm64)"
        echo "  2. Try a different region"
        echo "  3. Choose a different OS type"
        echo ""
        print_warning "Some OS types may not be available in all regions with all architectures"
        exit 1
    fi

    # Get AMI details
    local ami_name
    ami_name=$(aws ec2 describe-images \
        --image-ids "$VALIDATED_AMI_ID" \
        --query 'Images[0].Name' \
        --output text \
        --region "$AWS_REGION" 2>&1)

    print_success "AMI validated successfully!"
    print_info "AMI ID: $VALIDATED_AMI_ID"
    print_info "AMI Name: $ami_name"

    export TF_VAR_validated_ami_id="$VALIDATED_AMI_ID"
}

select_instance_type() {
    print_header "Instance Type Selection"

    local instance_types=()

    if [ "$ARCHITECTURE" == "arm64" ]; then
        instance_types=(
            "t4g.nano" "t4g.micro" "t4g.small" "t4g.medium" "t4g.large"
            "t4g.xlarge" "t4g.2xlarge" "m6g.medium" "m6g.large" "m6g.xlarge"
            "c6g.medium" "c6g.large" "c6g.xlarge" "r6g.medium" "r6g.large"
        )
    else
        instance_types=(
            "t2.micro" "t2.small" "t2.medium" "t2.large"
            "t3.nano" "t3.micro" "t3.small" "t3.medium" "t3.large" "t3.xlarge"
            "t3a.micro" "t3a.small" "t3a.medium" "t3a.large"
            "m5.large" "m5.xlarge" "m5.2xlarge" "m5.4xlarge"
            "c5.large" "c5.xlarge" "c5.2xlarge"
            "r5.large" "r5.xlarge" "r5.2xlarge"
        )
    fi

    echo -e "${YELLOW}Select Instance Type:${NC}"
    PS3="Enter your choice (number): "

    select INSTANCE_TYPE in "${instance_types[@]}"; do
        if [[ -n "$INSTANCE_TYPE" ]]; then
            export TF_VAR_instance_type="$INSTANCE_TYPE"
            print_success "Selected Instance Type: $INSTANCE_TYPE"
            break
        fi
    done
}

select_key_pair() {
    print_header "SSH Key Pair Configuration"

    local options=("Use existing key pair" "Create new key pair")

    echo -e "${YELLOW}Key Pair Options:${NC}"
    PS3="Enter your choice (number): "

    select choice in "${options[@]}"; do
        case $REPLY in
            1)
                KEY_PAIR_OPTION="existing"
                select_existing_key_pair
                break
                ;;
            2)
                KEY_PAIR_OPTION="create_new"
                create_new_key_name
                break
                ;;
        esac
    done
}

select_existing_key_pair() {
    print_info "Fetching existing key pairs..."

    local key_output
    key_output=$(aws ec2 describe-key-pairs \
        --query 'KeyPairs[*].KeyName' \
        --output text \
        --region "$AWS_REGION" 2>&1)

    if [ $? -ne 0 ] || [ -z "$key_output" ]; then
        print_warning "No existing key pairs found"
        KEY_PAIR_OPTION="create_new"
        create_new_key_name
        return
    fi

    local key_array=($key_output)

    echo -e "${YELLOW}Select existing key pair:${NC}"
    PS3="Enter your choice (number): "

    select KEY_NAME in "${key_array[@]}"; do
        if [[ -n "$KEY_NAME" ]]; then
            export TF_VAR_key_pair_option="existing"
            export TF_VAR_existing_key_name="$KEY_NAME"
            export TF_VAR_new_key_name=""
            print_success "Selected Key Pair: $KEY_NAME"
            break
        fi
    done
}

create_new_key_name() {
    read -p "Enter name for new key pair [default: ec2-key-$(date +%s)]: " KEY_NAME
    [ -z "$KEY_NAME" ] && KEY_NAME="ec2-key-$(date +%s)"

    export TF_VAR_key_pair_option="create_new"
    export TF_VAR_existing_key_name=""
    export TF_VAR_new_key_name="$KEY_NAME"
    print_success "New key pair will be created: $KEY_NAME"
}

select_security_group() {
    print_header "Security Group Configuration"

    local options=("Use existing security group" "Create new security group")

    echo -e "${YELLOW}Security Group Options:${NC}"
    PS3="Enter your choice (number): "

    select choice in "${options[@]}"; do
        case $REPLY in
            1)
                SECURITY_GROUP_OPTION="existing"
                select_existing_security_group
                break
                ;;
            2)
                SECURITY_GROUP_OPTION="create_new"
                create_new_sg_name
                break
                ;;
        esac
    done
}

select_existing_security_group() {
    print_info "Fetching existing security groups..."

    local sg_output
    sg_output=$(aws ec2 describe-security-groups \
        --query 'SecurityGroups[*].[GroupId,GroupName]' \
        --output text \
        --region "$AWS_REGION" 2>&1)

    if [ $? -ne 0 ] || [ -z "$sg_output" ]; then
        print_warning "No security groups found"
        SECURITY_GROUP_OPTION="create_new"
        create_new_sg_name
        return
    fi

    local sg_options=()
    while IFS=$'\t' read -r sg_id sg_name; do
        sg_options+=("$sg_id")
    done <<< "$sg_output"

    echo -e "${YELLOW}Select existing security group:${NC}"
    PS3="Enter your choice (number): "

    select SECURITY_GROUP_ID in "${sg_options[@]}"; do
        if [[ -n "$SECURITY_GROUP_ID" ]]; then
            export TF_VAR_security_group_option="existing"
            export TF_VAR_existing_security_group_id="$SECURITY_GROUP_ID"
            export TF_VAR_new_security_group_name=""
            print_success "Selected Security Group: $SECURITY_GROUP_ID"
            break
        fi
    done
}

create_new_sg_name() {
    read -p "Enter security group name [default: terraform-ec2-sg]: " SG_NAME
    [ -z "$SG_NAME" ] && SG_NAME="terraform-ec2-sg"

    export TF_VAR_security_group_option="create_new"
    export TF_VAR_existing_security_group_id=""
    export TF_VAR_new_security_group_name="$SG_NAME"
    print_success "New security group will be created: $SG_NAME"
}

configure_storage() {
    print_header "Storage Configuration"

    local volume_types=("gp3" "gp2" "io1" "io2" "st1" "sc1")

    echo -e "${YELLOW}Select volume type:${NC}"
    echo "1) gp3 - General Purpose SSD (Latest)"
    echo "2) gp2 - General Purpose SSD"
    echo "3) io1 - Provisioned IOPS SSD"
    echo "4) io2 - Provisioned IOPS SSD (Latest)"
    echo "5) st1 - Throughput Optimized HDD"
    echo "6) sc1 - Cold HDD"
    PS3="Enter your choice (number): "

    select VOLUME_TYPE in "${volume_types[@]}"; do
        if [[ -n "$VOLUME_TYPE" ]]; then
            export TF_VAR_root_volume_type="$VOLUME_TYPE"
            print_success "Selected Volume Type: $VOLUME_TYPE"
            break
        fi
    done

    read -p "Enter root volume size in GB [default: 8]: " VOLUME_SIZE
    VOLUME_SIZE=${VOLUME_SIZE:-8}
    export TF_VAR_root_volume_size="$VOLUME_SIZE"

    local encryption_options=("Yes" "No")
    echo -e "${YELLOW}Enable EBS encryption?${NC}"
    PS3="Enter your choice (number): "

    select encrypt_choice in "${encryption_options[@]}"; do
        if [[ -n "$encrypt_choice" ]]; then
            if [ "$encrypt_choice" == "Yes" ]; then
                export TF_VAR_enable_encryption="true"
            else
                export TF_VAR_enable_encryption="false"
            fi
            break
        fi
    done

    print_success "Volume Size: ${VOLUME_SIZE} GB"
    print_success "Encryption: ${TF_VAR_enable_encryption}"
}

set_instance_name() {
    print_header "Instance Name Configuration"

    read -p "Enter a name for your EC2 instance: " INSTANCE_NAME
    [ -z "$INSTANCE_NAME" ] && INSTANCE_NAME="EC2-Instance-$(date +%Y%m%d-%H%M%S)"

    export TF_VAR_instance_name="$INSTANCE_NAME"
    print_success "Instance Name: $INSTANCE_NAME"
}

#############################################################################
# Generate Terraform Files
#############################################################################

generate_terraform_files() {
    print_header "Generating Terraform Configuration"

    # Create Terraform directory
    mkdir -p "$TF_DIR"
    cd "$TF_DIR"

    print_info "Creating Terraform files in: $TF_DIR"

    # Generate provider.tf
    cat > provider.tf << 'EOF'
terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
    local = {
      source  = "hashicorp/local"
      version = "~> 2.0"
    }
  }
}

provider "aws" {
  region     = var.aws_region
  access_key = var.aws_access_key
  secret_key = var.aws_secret_key
}
EOF

    # Generate variables.tf
    cat > variables.tf << 'EOF'
variable "aws_access_key" {
  description = "AWS Access Key"
  type        = string
  sensitive   = true
}

variable "aws_secret_key" {
  description = "AWS Secret Key"
  type        = string
  sensitive   = true
}

variable "instance_name" {
  description = "Name tag for the EC2 instance"
  type        = string
}

variable "aws_region" {
  description = "AWS Region"
  type        = string
}

variable "os_type" {
  description = "Operating System Type"
  type        = string
}

variable "architecture" {
  description = "CPU Architecture"
  type        = string
}

variable "validated_ami_id" {
  description = "Pre-validated AMI ID"
  type        = string
}

variable "instance_type" {
  description = "EC2 Instance Type"
  type        = string
}

variable "key_pair_option" {
  description = "Key pair option: existing or create_new"
  type        = string
}

variable "existing_key_name" {
  description = "Name of existing key pair"
  type        = string
  default     = ""
}

variable "new_key_name" {
  description = "Name for new key pair"
  type        = string
  default     = ""
}

variable "security_group_option" {
  description = "Security group option: existing or create_new"
  type        = string
}

variable "existing_security_group_id" {
  description = "ID of existing security group"
  type        = string
  default     = ""
}

variable "new_security_group_name" {
  description = "Name for new security group"
  type        = string
  default     = "terraform-ec2-sg"
}

variable "root_volume_size" {
  description = "Size of root volume in GB"
  type        = number
  default     = 8
}

variable "root_volume_type" {
  description = "Type of root volume"
  type        = string
  default     = "gp3"
}

variable "enable_encryption" {
  description = "Enable EBS encryption"
  type        = bool
  default     = true
}
EOF

    # Generate locals.tf
    cat > locals.tf << 'EOF'
locals {
  key_name          = var.key_pair_option == "existing" ? var.existing_key_name : (var.key_pair_option == "create_new" ? aws_key_pair.new[0].key_name : "")
  security_group_id = var.security_group_option == "existing" ? var.existing_security_group_id : aws_security_group.new[0].id
}
EOF

    # Generate data.tf
    cat > data.tf << 'EOF'
data "aws_vpc" "default" {
  default = true
}

data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_security_group" "existing" {
  count = var.security_group_option == "existing" ? 1 : 0
  id    = var.existing_security_group_id
}

data "aws_key_pair" "existing" {
  count    = var.key_pair_option == "existing" ? 1 : 0
  key_name = var.existing_key_name
}
EOF

    # Generate keypair.tf
    cat > keypair.tf << 'EOF'
resource "tls_private_key" "ec2_key" {
  count     = var.key_pair_option == "create_new" ? 1 : 0
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "new" {
  count      = var.key_pair_option == "create_new" ? 1 : 0
  key_name   = var.new_key_name != "" ? var.new_key_name : "${var.instance_name}-key"
  public_key = tls_private_key.ec2_key[0].public_key_openssh

  tags = {
    Name = var.new_key_name != "" ? var.new_key_name : "${var.instance_name}-key"
  }
}

resource "local_file" "private_key" {
  count           = var.key_pair_option == "create_new" ? 1 : 0
  content         = tls_private_key.ec2_key[0].private_key_pem
  filename        = "${path.module}/${aws_key_pair.new[0].key_name}.pem"
  file_permission = "0400"
}
EOF

    # Generate security_group.tf
    cat > security_group.tf << 'EOF'
resource "aws_security_group" "new" {
  count       = var.security_group_option == "create_new" ? 1 : 0
  name        = var.new_security_group_name
  description = "Security group for ${var.instance_name}"
  vpc_id      = data.aws_vpc.default.id

  dynamic "ingress" {
    for_each = contains(["windows-2022", "windows-2019"], var.os_type) ? [] : [1]
    content {
      description = "SSH access"
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }

  dynamic "ingress" {
    for_each = contains(["windows-2022", "windows-2019"], var.os_type) ? [1] : []
    content {
      description = "RDP access"
      from_port   = 3389
      to_port     = 3389
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }

  ingress {
    description = "HTTP access"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTPS access"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Allow all outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = var.new_security_group_name
  }

  lifecycle {
    create_before_destroy = true
  }
}
EOF

    # Generate main.tf (UPDATED - uses validated AMI ID directly)
    cat > main.tf << 'EOF'
resource "aws_instance" "ec2" {
  ami                    = var.validated_ami_id
  instance_type          = var.instance_type
  key_name               = local.key_name
  vpc_security_group_ids = [local.security_group_id]
  availability_zone      = data.aws_availability_zones.available.names[0]

  root_block_device {
    volume_size           = var.root_volume_size
    volume_type           = var.root_volume_type
    encrypted             = var.enable_encryption
    delete_on_termination = true

    tags = {
      Name = "${var.instance_name}-root-volume"
    }
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "enabled"
  }

  tags = {
    Name         = var.instance_name
    OS           = var.os_type
    Architecture = var.architecture
  }

  depends_on = [
    aws_security_group.new,
    aws_key_pair.new
  ]
}
EOF

    # Generate outputs.tf
    cat > outputs.tf << 'EOF'
output "instance_id" {
  description = "ID of the EC2 instance"
  value       = aws_instance.ec2.id
}

output "instance_public_ip" {
  description = "Public IP address of the EC2 instance"
  value       = aws_instance.ec2.public_ip
}

output "instance_private_ip" {
  description = "Private IP address of the EC2 instance"
  value       = aws_instance.ec2.private_ip
}

output "instance_state" {
  description = "State of the EC2 instance"
  value       = aws_instance.ec2.instance_state
}

output "ami_id" {
  description = "AMI ID used for the instance"
  value       = var.validated_ami_id
}

output "security_group_id" {
  description = "ID of the security group"
  value       = local.security_group_id
}

output "key_pair_name" {
  description = "Name of the key pair used"
  value       = local.key_name
}

output "private_key_path" {
  description = "Path to private key file (if created)"
  value       = var.key_pair_option == "create_new" ? "${path.module}/${aws_key_pair.new[0].key_name}.pem" : "Using existing key pair"
}

output "ssh_connection_command" {
  description = "SSH connection command"
  value = contains(["windows-2022", "windows-2019"], var.os_type) ? "Use RDP to connect on port 3389" : (
    var.key_pair_option == "create_new" ?
    "ssh -i ${aws_key_pair.new[0].key_name}.pem ec2-user@${aws_instance.ec2.public_ip}" :
    "ssh -i <your-key>.pem ec2-user@${aws_instance.ec2.public_ip}"
  )
}

output "availability_zone" {
  description = "Availability zone of the instance"
  value       = aws_instance.ec2.availability_zone
}
EOF

    print_success "Terraform configuration files generated successfully"
}

#############################################################################
# Execute Terraform
#############################################################################

execute_terraform() {
    print_header "Executing Terraform"

    cd "$TF_DIR"

    # Display configuration summary
    print_info "Configuration Summary:"
    echo "  Instance Name:    ${TF_VAR_instance_name}"
    echo "  Region:           ${TF_VAR_aws_region}"
    echo "  OS:               ${TF_VAR_os_type}"
    echo "  Architecture:     ${TF_VAR_architecture}"
    echo "  AMI ID:           ${TF_VAR_validated_ami_id}"
    echo "  Instance Type:    ${TF_VAR_instance_type}"
    echo "  Key Pair Option:  ${TF_VAR_key_pair_option}"
    echo "  Security Group:   ${TF_VAR_security_group_option}"
    echo "  Volume Type:      ${TF_VAR_root_volume_type}"
    echo "  Volume Size:      ${TF_VAR_root_volume_size} GB"
    echo "  Encryption:       ${TF_VAR_enable_encryption}"
    echo

    read -p "Do you want to proceed with Terraform? (yes/no): " confirm
    if [[ ! "$confirm" =~ ^[Yy][Ee][Ss]$ ]] && [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        print_warning "Deployment cancelled by user"
        exit 0
    fi

    # Terraform init
    print_info "Initializing Terraform..."
    if ! terraform init; then
        error_exit "Terraform init failed"
    fi
    print_success "Terraform initialized"

    # Terraform validate
    print_info "Validating Terraform configuration..."
    if ! terraform validate; then
        error_exit "Terraform validation failed"
    fi
    print_success "Terraform configuration validated"

    # Terraform plan
    print_info "Creating Terraform execution plan..."
    if ! terraform plan -out=tfplan; then
        error_exit "Terraform plan failed"
    fi
    print_success "Terraform plan created"

    # Terraform apply
    print_info "Applying Terraform configuration..."
    if ! terraform apply -auto-approve tfplan; then
        error_exit "Terraform apply failed"
    fi
    print_success "Terraform apply completed successfully"

    # Display outputs
    print_header "Deployment Complete!"
    terraform output
}

#############################################################################
# Cleanup Function
#############################################################################

cleanup_terraform() {
    print_header "Cleanup Terraform Resources"

    if [ ! -d "$TF_DIR" ]; then
        print_error "Terraform directory not found: $TF_DIR"
        exit 1
    fi

    cd "$TF_DIR"

    if [ ! -f "terraform.tfstate" ]; then
        print_error "No Terraform state found. Nothing to destroy."
        exit 1
    fi

    print_warning "This will destroy all resources created by Terraform!"
    read -p "Are you sure you want to continue? (yes/no): " confirm

    if [[ "$confirm" =~ ^[Yy][Ee][Ss]$ ]] || [[ "$confirm" =~ ^[Yy]$ ]]; then
        print_info "Destroying Terraform resources..."
        terraform destroy -auto-approve
        print_success "All resources destroyed"
    else
        print_info "Cleanup cancelled"
    fi
}

#############################################################################
# Main Function
#############################################################################

main() {
    clear
    print_header "AWS EC2 Deployment with Terraform Backend"

    # Check for cleanup flag
    if [ "${1:-}" == "--cleanup" ] || [ "${1:-}" == "--destroy" ]; then
        load_aws_credentials
        cleanup_terraform
        exit 0
    fi

    # Validate prerequisites
    validate_prerequisites

    # Load AWS credentials from config file
    load_aws_credentials

    # Interactive selections
    set_instance_name
    select_region
    select_os_type
    select_architecture

    # IMPORTANT: Validate AMI before proceeding
    validate_ami_availability

    select_instance_type
    select_key_pair
    select_security_group
    configure_storage

    # Generate Terraform configuration
    generate_terraform_files

    # Execute Terraform
    execute_terraform

    print_header "🎉 SUCCESS! EC2 Instance Created Successfully!"
}

#############################################################################
# Script Entry Point
#############################################################################

main "$@"
