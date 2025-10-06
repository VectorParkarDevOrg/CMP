#!/bin/bash

#############################################################################
# AWS EC2 Interactive Deployment Script
# Description: Fully interactive script to launch EC2 instances with AWS CLI
# Author: Infrastructure Automation
# Version: 3.0 - WITH PROPER ERROR HANDLING
#############################################################################

# Enable error handling but with better control
set -u  # Exit on undefined variable
set -o pipefail  # Catch errors in pipes

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Global variables
INSTANCE_ID=""
TEMP_FILES=()

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

cleanup() {
    if [ ${#TEMP_FILES[@]} -gt 0 ]; then
        print_info "Cleaning up temporary files..."
        for file in "${TEMP_FILES[@]}"; do
            [ -f "$file" ] && rm -f "$file"
        done
    fi
}

trap cleanup EXIT

error_exit() {
    print_error "$1"
    exit 1
}

validate_aws_cli() {
    if ! command -v aws &> /dev/null; then
        error_exit "AWS CLI is not installed. Please install it first."
    fi
    print_success "AWS CLI found"
}

#############################################################################
# AWS Credentials Setup
#############################################################################

setup_aws_credentials() {
    print_header "AWS Credentials Setup"

    read -p "Enter AWS Access Key ID: " AWS_ACCESS_KEY
    [ -z "$AWS_ACCESS_KEY" ] && error_exit "Access Key cannot be empty"

    read -sp "Enter AWS Secret Access Key: " AWS_SECRET_KEY
    echo
    [ -z "$AWS_SECRET_KEY" ] && error_exit "Secret Key cannot be empty"

    export AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY"
    export AWS_SECRET_ACCESS_KEY="$AWS_SECRET_KEY"

    # Test credentials
    print_info "Validating AWS credentials..."
    local test_output
    test_output=$(aws sts get-caller-identity 2>&1)

    if [ $? -eq 0 ]; then
        print_success "AWS credentials validated successfully"
        ACCOUNT_ID=$(echo "$test_output" | grep -oP '"Account":\s*"\K[^"]+')
        print_info "AWS Account ID: $ACCOUNT_ID"
    else
        print_error "Failed to validate credentials:"
        echo "$test_output"
        exit 1
    fi
}

#############################################################################
# Region Selection
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
            print_success "Selected Region: $AWS_REGION"
            break
        else
            print_error "Invalid selection. Please try again."
        fi
    done
}

#############################################################################
# OS Type and AMI Selection
#############################################################################

select_os_type() {
    print_header "Operating System Selection"

    local os_types=(
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

    select OS_TYPE in "${os_types[@]}"; do
        if [[ -n "$OS_TYPE" ]]; then
            print_success "Selected OS: $OS_TYPE"
            break
        else
            print_error "Invalid selection. Please try again."
        fi
    done
}

#############################################################################
# Architecture Selection
#############################################################################

select_architecture() {
    print_header "CPU Architecture Selection"

    local architectures=("x86_64" "arm64")

    echo -e "${YELLOW}Select CPU Architecture:${NC}"
    echo "1) x86_64 (Intel/AMD 64-bit)"
    echo "2) arm64 (AWS Graviton)"
    PS3="Enter your choice (number): "

    select ARCHITECTURE in "${architectures[@]}"; do
        if [[ -n "$ARCHITECTURE" ]]; then
            print_success "Selected Architecture: $ARCHITECTURE"
            break
        else
            print_error "Invalid selection. Please try again."
        fi
    done
}

#############################################################################
# Get Latest AMI
#############################################################################

get_latest_ami() {
    print_info "Fetching latest AMI for $OS_TYPE ($ARCHITECTURE) in $AWS_REGION..."

    local ami_name_pattern=""
    local ami_owner=""

    case "$OS_TYPE" in
        "Amazon Linux 2023")
            ami_name_pattern="al2023-ami-*-kernel-*"
            ami_owner="amazon"
            ;;
        "Amazon Linux 2")
            ami_name_pattern="amzn2-ami-hvm-*"
            ami_owner="amazon"
            ;;
        "Ubuntu 22.04 LTS")
            ami_name_pattern="ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-*-server-*"
            ami_owner="099720109477"
            ;;
        "Ubuntu 20.04 LTS")
            ami_name_pattern="ubuntu/images/hvm-ssd/ubuntu-focal-20.04-*-server-*"
            ami_owner="099720109477"
            ;;
        "Ubuntu 24.04 LTS")
            ami_name_pattern="ubuntu/images/hvm-ssd/ubuntu-noble-24.04-*-server-*"
            ami_owner="099720109477"
            ;;
        "Debian 12")
            ami_name_pattern="debian-12-*"
            ami_owner="136693071363"
            ;;
        "Debian 11")
            ami_name_pattern="debian-11-*"
            ami_owner="136693071363"
            ;;
        "Red Hat Enterprise Linux 9")
            ami_name_pattern="RHEL-9*_HVM-*"
            ami_owner="309956199498"
            ;;
        "Red Hat Enterprise Linux 8")
            ami_name_pattern="RHEL-8*_HVM-*"
            ami_owner="309956199498"
            ;;
        "Windows Server 2022")
            ami_name_pattern="Windows_Server-2022-English-Full-Base-*"
            ami_owner="amazon"
            ;;
        "Windows Server 2019")
            ami_name_pattern="Windows_Server-2019-English-Full-Base-*"
            ami_owner="amazon"
            ;;
        "SUSE Linux 15")
            ami_name_pattern="suse-sles-15-*"
            ami_owner="amazon"
            ;;
    esac

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
        print_error "Failed to fetch AMI:"
        echo "$ami_output"
        exit 1
    fi

    AMI_ID="$ami_output"

    if [ -z "$AMI_ID" ] || [ "$AMI_ID" == "None" ]; then
        error_exit "No AMI found for $OS_TYPE with architecture $ARCHITECTURE in region $AWS_REGION"
    fi

    AMI_NAME=$(aws ec2 describe-images \
        --image-ids "$AMI_ID" \
        --query 'Images[0].Name' \
        --output text \
        --region "$AWS_REGION" 2>&1)

    print_success "Found AMI: $AMI_ID"
    print_info "AMI Name: $AMI_NAME"
}

#############################################################################
# Instance Type Selection
#############################################################################

select_instance_type() {
    print_header "Instance Type Selection"

    local instance_types=()

    # Filter for architecture
    if [ "$ARCHITECTURE" == "arm64" ]; then
        instance_types=(
            "t4g.nano"
            "t4g.micro"
            "t4g.small"
            "t4g.medium"
            "t4g.large"
            "t4g.xlarge"
            "t4g.2xlarge"
            "m6g.medium"
            "m6g.large"
            "m6g.xlarge"
            "m6g.2xlarge"
            "c6g.medium"
            "c6g.large"
            "c6g.xlarge"
            "c6g.2xlarge"
            "r6g.medium"
            "r6g.large"
            "r6g.xlarge"
        )
    else
        instance_types=(
            "t2.micro"
            "t2.small"
            "t2.medium"
            "t2.large"
            "t2.xlarge"
            "t3.nano"
            "t3.micro"
            "t3.small"
            "t3.medium"
            "t3.large"
            "t3.xlarge"
            "t3.2xlarge"
            "t3a.micro"
            "t3a.small"
            "t3a.medium"
            "t3a.large"
            "m5.large"
            "m5.xlarge"
            "m5.2xlarge"
            "m5.4xlarge"
            "c5.large"
            "c5.xlarge"
            "c5.2xlarge"
            "c5.4xlarge"
            "r5.large"
            "r5.xlarge"
            "r5.2xlarge"
        )
    fi

    echo -e "${YELLOW}Select Instance Type:${NC}"
    PS3="Enter your choice (number): "

    select INSTANCE_TYPE in "${instance_types[@]}"; do
        if [[ -n "$INSTANCE_TYPE" ]]; then
            print_success "Selected Instance Type: $INSTANCE_TYPE"
            break
        else
            print_error "Invalid selection. Please try again."
        fi
    done
}

#############################################################################
# Key Pair Management
#############################################################################

select_key_pair() {
    print_header "SSH Key Pair Configuration"

    local options=("Use existing key pair" "Create new key pair")

    echo -e "${YELLOW}Key Pair Options:${NC}"
    PS3="Enter your choice (number): "

    select choice in "${options[@]}"; do
        case $REPLY in
            1)
                select_existing_key_pair
                break
                ;;
            2)
                create_new_key_pair
                break
                ;;
            *)
                print_error "Invalid selection. Please try again."
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

    if [ $? -ne 0 ]; then
        print_error "Failed to fetch key pairs:"
        echo "$key_output"
        create_new_key_pair
        return
    fi

    if [ -z "$key_output" ]; then
        print_warning "No existing key pairs found in region $AWS_REGION"
        create_new_key_pair
        return
    fi

    local key_array=($key_output)

    echo -e "${YELLOW}Select existing key pair:${NC}"
    PS3="Enter your choice (number): "

    select KEY_NAME in "${key_array[@]}"; do
        if [[ -n "$KEY_NAME" ]]; then
            print_success "Selected Key Pair: $KEY_NAME"
            print_warning "Make sure you have the private key file (.pem) for this key pair"
            break
        else
            print_error "Invalid selection. Please try again."
        fi
    done
}

create_new_key_pair() {
    print_info "Creating new key pair..."

    read -p "Enter name for new key pair: " KEY_NAME
    [ -z "$KEY_NAME" ] && KEY_NAME="ec2-key-$(date +%s)"

    # Check if key pair already exists
    if aws ec2 describe-key-pairs --key-names "$KEY_NAME" --region "$AWS_REGION" &>/dev/null; then
        print_error "Key pair '$KEY_NAME' already exists."
        read -p "Enter a different name: " KEY_NAME
        [ -z "$KEY_NAME" ] && error_exit "Key pair name cannot be empty"
    fi

    local key_file="${KEY_NAME}.pem"

    local key_output
    key_output=$(aws ec2 create-key-pair \
        --key-name "$KEY_NAME" \
        --query 'KeyMaterial' \
        --output text \
        --region "$AWS_REGION" 2>&1)

    if [ $? -ne 0 ]; then
        print_error "Failed to create key pair:"
        echo "$key_output"
        exit 1
    fi

    echo "$key_output" > "$key_file"
    chmod 400 "$key_file"

    print_success "Key pair created: $KEY_NAME"
    print_success "Private key saved to: $(pwd)/$key_file"
    print_warning "Keep this file safe! You won't be able to download it again."
}

#############################################################################
# Security Group Management
#############################################################################

select_security_group() {
    print_header "Security Group Configuration"

    local options=("Use existing security group" "Create new security group")

    echo -e "${YELLOW}Security Group Options:${NC}"
    PS3="Enter your choice (number): "

    select choice in "${options[@]}"; do
        case $REPLY in
            1)
                select_existing_security_group
                break
                ;;
            2)
                create_new_security_group
                break
                ;;
            *)
                print_error "Invalid selection. Please try again."
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

    if [ $? -ne 0 ]; then
        print_error "Failed to fetch security groups:"
        echo "$sg_output"
        create_new_security_group
        return
    fi

    if [ -z "$sg_output" ]; then
        print_warning "No security groups found"
        create_new_security_group
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
            print_success "Selected Security Group: $SECURITY_GROUP_ID"
            break
        else
            print_error "Invalid selection. Please try again."
        fi
    done
}

create_new_security_group() {
    print_info "Creating new security group..."

    read -p "Enter security group name [default: ec2-sg-$(date +%s)]: " SG_NAME
    [ -z "$SG_NAME" ] && SG_NAME="ec2-sg-$(date +%s)"

    read -p "Enter security group description [default: Security group for EC2]: " SG_DESC
    [ -z "$SG_DESC" ] && SG_DESC="Security group for EC2 instance"

    # Get default VPC
    print_info "Finding default VPC..."
    local vpc_output
    vpc_output=$(aws ec2 describe-vpcs \
        --filters "Name=isDefault,Values=true" \
        --query 'Vpcs[0].VpcId' \
        --output text \
        --region "$AWS_REGION" 2>&1)

    if [ $? -ne 0 ]; then
        print_error "Failed to find VPC:"
        echo "$vpc_output"
        exit 1
    fi

    VPC_ID="$vpc_output"

    if [ -z "$VPC_ID" ] || [ "$VPC_ID" == "None" ]; then
        error_exit "No default VPC found in region $AWS_REGION"
    fi

    print_info "Using VPC: $VPC_ID"

    local sg_output
    sg_output=$(aws ec2 create-security-group \
        --group-name "$SG_NAME" \
        --description "$SG_DESC" \
        --vpc-id "$VPC_ID" \
        --query 'GroupId' \
        --output text \
        --region "$AWS_REGION" 2>&1)

    if [ $? -ne 0 ]; then
        print_error "Failed to create security group:"
        echo "$sg_output"
        exit 1
    fi

    SECURITY_GROUP_ID="$sg_output"
    print_success "Security group created: $SECURITY_GROUP_ID"

    # Add rules based on OS type
    if [[ "$OS_TYPE" == *"Windows"* ]]; then
        print_info "Adding RDP rule (port 3389)..."
        aws ec2 authorize-security-group-ingress \
            --group-id "$SECURITY_GROUP_ID" \
            --protocol tcp \
            --port 3389 \
            --cidr 0.0.0.0/0 \
            --region "$AWS_REGION" &>/dev/null
        print_success "RDP access enabled"
    else
        print_info "Adding SSH rule (port 22)..."
        aws ec2 authorize-security-group-ingress \
            --group-id "$SECURITY_GROUP_ID" \
            --protocol tcp \
            --port 22 \
            --cidr 0.0.0.0/0 \
            --region "$AWS_REGION" &>/dev/null
        print_success "SSH access enabled"
    fi

    # Add HTTP and HTTPS
    print_info "Adding HTTP/HTTPS rules..."
    aws ec2 authorize-security-group-ingress \
        --group-id "$SECURITY_GROUP_ID" \
        --protocol tcp \
        --port 80 \
        --cidr 0.0.0.0/0 \
        --region "$AWS_REGION" &>/dev/null

    aws ec2 authorize-security-group-ingress \
        --group-id "$SECURITY_GROUP_ID" \
        --protocol tcp \
        --port 443 \
        --cidr 0.0.0.0/0 \
        --region "$AWS_REGION" &>/dev/null

    print_success "HTTP/HTTPS access enabled"
}

#############################################################################
# Storage Configuration
#############################################################################

configure_storage() {
    print_header "Storage Configuration"

    local volume_types=("gp3" "gp2" "io1" "io2" "st1" "sc1")

    echo -e "${YELLOW}Select volume type:${NC}"
    echo "1) gp3 - General Purpose SSD (Latest, Cost-effective)"
    echo "2) gp2 - General Purpose SSD (Previous generation)"
    echo "3) io1 - Provisioned IOPS SSD (High performance)"
    echo "4) io2 - Provisioned IOPS SSD (Latest, High durability)"
    echo "5) st1 - Throughput Optimized HDD (Big data)"
    echo "6) sc1 - Cold HDD (Infrequent access)"
    PS3="Enter your choice (number): "

    select VOLUME_TYPE in "${volume_types[@]}"; do
        if [[ -n "$VOLUME_TYPE" ]]; then
            print_success "Selected Volume Type: $VOLUME_TYPE"
            break
        else
            print_error "Invalid selection. Please try again."
        fi
    done

    # Volume Size
    read -p "Enter root volume size in GB [default: 8, min: 8, max: 16384]: " VOLUME_SIZE
    VOLUME_SIZE=${VOLUME_SIZE:-8}

    if ! [[ "$VOLUME_SIZE" =~ ^[0-9]+$ ]] || [ "$VOLUME_SIZE" -lt 8 ] || [ "$VOLUME_SIZE" -gt 16384 ]; then
        print_warning "Invalid size. Using default: 8 GB"
        VOLUME_SIZE=8
    fi

    # Encryption
    local encryption_options=("Yes" "No")

    echo -e "${YELLOW}Enable EBS encryption?${NC}"
    PS3="Enter your choice (number): "

    select encrypt_choice in "${encryption_options[@]}"; do
        if [[ -n "$encrypt_choice" ]]; then
            if [ "$encrypt_choice" == "Yes" ]; then
                ENCRYPTION="true"
            else
                ENCRYPTION="false"
            fi
            break
        else
            print_error "Invalid selection. Please try again."
        fi
    done

    print_success "Volume Size: ${VOLUME_SIZE} GB"
    print_success "Encryption: $ENCRYPTION"
}

#############################################################################
# Instance Name
#############################################################################

set_instance_name() {
    print_header "Instance Name Configuration"

    read -p "Enter a name for your EC2 instance: " INSTANCE_NAME
    [ -z "$INSTANCE_NAME" ] && INSTANCE_NAME="EC2-Instance-$(date +%Y%m%d-%H%M%S)"

    print_success "Instance Name: $INSTANCE_NAME"
}

#############################################################################
# Launch EC2 Instance
#############################################################################

launch_instance() {
    print_header "Launching EC2 Instance"

    print_info "Configuration Summary:"
    echo "  Instance Name:    $INSTANCE_NAME"
    echo "  Region:           $AWS_REGION"
    echo "  OS:               $OS_TYPE"
    echo "  Architecture:     $ARCHITECTURE"
    echo "  AMI ID:           $AMI_ID"
    echo "  Instance Type:    $INSTANCE_TYPE"
    echo "  Key Pair:         $KEY_NAME"
    echo "  Security Group:   $SECURITY_GROUP_ID"
    echo "  Volume Type:      $VOLUME_TYPE"
    echo "  Volume Size:      ${VOLUME_SIZE} GB"
    echo "  Encryption:       $ENCRYPTION"
    echo

    read -p "Do you want to proceed with the launch? (yes/no): " confirm
    if [[ ! "$confirm" =~ ^[Yy][Ee][Ss]$ ]] && [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        error_exit "Launch cancelled by user"
    fi

    print_info "Launching instance..."

    # Determine root device name based on OS
    if [[ "$OS_TYPE" == *"Windows"* ]]; then
        DEVICE_NAME="/dev/sda1"
    else
        DEVICE_NAME="/dev/xvda"
    fi

    # Create the launch command with proper error handling
    print_info "Executing AWS run-instances command..."

    local launch_output
    launch_output=$(aws ec2 run-instances \
        --image-id "$AMI_ID" \
        --instance-type "$INSTANCE_TYPE" \
        --key-name "$KEY_NAME" \
        --security-group-ids "$SECURITY_GROUP_ID" \
        --block-device-mappings "[{\"DeviceName\":\"$DEVICE_NAME\",\"Ebs\":{\"VolumeSize\":$VOLUME_SIZE,\"VolumeType\":\"$VOLUME_TYPE\",\"DeleteOnTermination\":true,\"Encrypted\":$ENCRYPTION}}]" \
        --metadata-options "HttpTokens=required,HttpPutResponseHopLimit=1,HttpEndpoint=enabled" \
        --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=\"$INSTANCE_NAME\"},{Key=OS,Value=\"$OS_TYPE\"},{Key=Architecture,Value=\"$ARCHITECTURE\"}]" \
        --region "$AWS_REGION" 2>&1)

    local exit_code=$?

    if [ $exit_code -ne 0 ]; then
        print_error "Failed to launch instance!"
        echo ""
        echo "Error output:"
        echo "$launch_output"
        echo ""
        print_info "Common causes:"
        echo "  1. IAM permissions insufficient (need ec2:RunInstances)"
        echo "  2. Instance limit exceeded for this instance type in the region"
        echo "  3. Invalid subnet or availability zone"
        echo "  4. Insufficient capacity in the region"
        echo "  5. Key pair or security group not accessible"
        exit 1
    fi

    # Extract instance ID
    INSTANCE_ID=$(echo "$launch_output" | grep -oP '"InstanceId":\s*"\K[^"]+' | head -1)

    if [ -z "$INSTANCE_ID" ]; then
        print_error "Failed to extract instance ID from response"
        echo "Full output:"
        echo "$launch_output"
        exit 1
    fi

    print_success "Instance launched successfully!"
    print_success "Instance ID: $INSTANCE_ID"

    wait_for_instance
}

#############################################################################
# Wait for Instance to be Running
#############################################################################

wait_for_instance() {
    print_info "Waiting for instance to be in 'running' state..."

    local max_attempts=60
    local attempt=0

    while [ $attempt -lt $max_attempts ]; do
        local state_output
        state_output=$(aws ec2 describe-instances \
            --instance-ids "$INSTANCE_ID" \
            --query 'Reservations[0].Instances[0].State.Name' \
            --output text \
            --region "$AWS_REGION" 2>&1)

        if [ $? -ne 0 ]; then
            print_error "Failed to check instance state"
            echo "$state_output"
            exit 1
        fi

        STATE="$state_output"

        if [ "$STATE" == "running" ]; then
            echo ""
            print_success "Instance is now running!"
            get_instance_details
            return 0
        elif [ "$STATE" == "pending" ]; then
            echo -n "."
            sleep 5
            ((attempt++))
        else
            error_exit "Instance entered unexpected state: $STATE"
        fi
    done

    print_warning "Timeout waiting for instance to start. Instance ID: $INSTANCE_ID"
    print_info "Check instance status with: aws ec2 describe-instances --instance-ids $INSTANCE_ID --region $AWS_REGION"
}

#############################################################################
# Get Instance Details
#############################################################################

get_instance_details() {
    print_header "Instance Details"

    # Wait a bit for public IP assignment
    sleep 5

    local instance_output
    instance_output=$(aws ec2 describe-instances \
        --instance-ids "$INSTANCE_ID" \
        --region "$AWS_REGION" 2>&1)

    if [ $? -ne 0 ]; then
        print_error "Failed to get instance details"
        echo "$instance_output"
        exit 1
    fi

    PUBLIC_IP=$(echo "$instance_output" | grep -oP '"PublicIpAddress":\s*"\K[^"]+' | head -1)
    PRIVATE_IP=$(echo "$instance_output" | grep -oP '"PrivateIpAddress":\s*"\K[^"]+' | head -1)
    AZ=$(echo "$instance_output" | grep -oP '"AvailabilityZone":\s*"\K[^"]+' | head -1)

    [ -z "$PUBLIC_IP" ] && PUBLIC_IP="N/A"
    [ -z "$PRIVATE_IP" ] && PRIVATE_IP="N/A"
    [ -z "$AZ" ] && AZ="N/A"

    echo "  Instance ID:       $INSTANCE_ID"
    echo "  Instance Name:     $INSTANCE_NAME"
    echo "  Instance Type:     $INSTANCE_TYPE"
    echo "  AMI ID:            $AMI_ID"
    echo "  Public IP:         ${PUBLIC_IP}"
    echo "  Private IP:        ${PRIVATE_IP}"
    echo "  Availability Zone: $AZ"
    echo "  Region:            $AWS_REGION"
    echo "  Key Pair:          $KEY_NAME"
    echo "  Security Group:    $SECURITY_GROUP_ID"
    echo

    if [[ "$OS_TYPE" == *"Windows"* ]]; then
        print_info "Connection Instructions:"
        echo "  Use RDP client to connect:"
        echo "  Host: $PUBLIC_IP"
        echo "  Port: 3389"
        echo ""
        echo "  To get the Administrator password, run:"
        echo "  aws ec2 get-password-data --instance-id $INSTANCE_ID --priv-launch-key-file ${KEY_NAME}.pem --region $AWS_REGION"
    else
        print_info "SSH Connection Command:"

        # Determine default username
        local username="ec2-user"
        if [[ "$OS_TYPE" == *"Ubuntu"* ]]; then
            username="ubuntu"
        elif [[ "$OS_TYPE" == *"Debian"* ]]; then
            username="admin"
        elif [[ "$OS_TYPE" == *"Red Hat"* ]]; then
            username="ec2-user"
        fi

        if [ -f "${KEY_NAME}.pem" ]; then
            echo "  ssh -i ${KEY_NAME}.pem ${username}@${PUBLIC_IP}"
        else
            echo "  ssh -i /path/to/${KEY_NAME}.pem ${username}@${PUBLIC_IP}"
        fi
    fi

    echo ""
    print_success "EC2 Instance deployment completed successfully!"
    print_info "You can view your instance in AWS Console or use AWS CLI to manage it."
}

#############################################################################
# Main Function
#############################################################################

main() {
    clear
    print_header "AWS EC2 Interactive Deployment Script"

    # Validate prerequisites
    validate_aws_cli

    # Step 1: AWS Credentials
    setup_aws_credentials

    # Step 2: Instance Name
    set_instance_name

    # Step 3: Region Selection
    select_region

    # Step 4: OS Selection
    select_os_type

    # Step 5: Architecture Selection
    select_architecture

    # Step 6: Get AMI
    get_latest_ami

    # Step 7: Instance Type Selection
    select_instance_type

    # Step 8: Key Pair Configuration
    select_key_pair

    # Step 9: Security Group Configuration
    select_security_group

    # Step 10: Storage Configuration
    configure_storage

    # Step 11: Launch Instance
    launch_instance

    print_header "Deployment Complete!"
}

#############################################################################
# Script Entry Point
#############################################################################

# Run main function
main "$@"
