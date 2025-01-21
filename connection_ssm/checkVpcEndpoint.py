# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: LicenseRef-.amazon.com.-AmznSL-1.0
# Licensed under the Amazon Software License  http://aws.amazon.com/asl/

import ipaddress
from ipaddress import ip_network
from typing import Dict, List
import argparse

import boto3
from botocore.exceptions import ClientError

ec2_client = boto3.client("ec2")


def get_vpc_cidr_block(vpc_id) -> str:
    try:
        response = ec2_client.describe_vpcs(VpcIds=[vpc_id])
    except ClientError as e:
        raise RuntimeError(f"[ERROR] An error occurred while trying to describe the VPC {vpc_id}: {str(e)}") from None

    return response.get("Vpcs", [])[0].get("CidrBlock")


def get_ssm_vpc_endpoints(vpc_id, ssm_enpoint_name) -> dict:
    try:
        response = ec2_client.describe_vpc_endpoints(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "service-name", "Values": [ssm_enpoint_name]}]
        )
    except ClientError as e:
        raise RuntimeError(
            f"[ERROR] An error occurred while trying to describe the VPC endpoint {ssm_enpoint_name} for {vpc_id}: {str(e)}"
        ) from None

    ssm_endpoints = response.get("VpcEndpoints", [])
    for endpoint in ssm_endpoints:
        if endpoint["State"].lower() == "available":
            return endpoint
        else:
            print(f"[WARNING] VPC endpoint '{endpoint['VpcEndpointId']}' is not in 'Available' state.")
            return {}
    else:
        return {}


def validate_segurity_groups(vpce_security_groups, instance_private_ip, instance_security_groups) -> str:
    https_port = 443
    for vpce_security_group in vpce_security_groups:
        try:
            response = ec2_client.describe_security_groups(GroupIds=[vpce_security_group])
        except ClientError as e:
            raise RuntimeError(
                f"[ERROR] An error occurred while trying to describe the security group {vpce_security_group}: {str(e)}"
            ) from None

        for sg in response.get("SecurityGroups", []):
            for rule in sg.get("IpPermissions", []):
                if (
                    (rule.get("IpProtocol") == "-1")
                    or (rule.get("FromPort") == -1 and rule.get("ToPort") == -1)
                    or (https_port in range(rule.get("FromPort"), rule.get("ToPort") + 1))
                ):
                    for cidr in rule.get("IpRanges", []):
                        if ipaddress.ip_address(instance_private_ip) in ip_network(cidr["CidrIp"], strict=False):
                            return f"[OK] VPC endpoint security group '{vpce_security_group}' allows traffic on port '{https_port}' from the instance private IP '{instance_private_ip}'."

                    for group in rule.get("UserIdGroupPairs", []):
                        for security_group_id in instance_security_groups:
                            if security_group_id in group["GroupId"]:
                                return f"[OK] VPC endpoint security group '{vpce_security_group}' allows traffic on port {https_port} from the instance security group {security_group_id}."

    # If we reach this point, it means that the security group does not allow traffic from the instance.
    error_text = f"[ERROR] VPC endpoint security groups '{', '.join(vpce_security_groups)}' do not allow traffic on port '{https_port}' from the instance security group(s) '{', '.join(instance_security_groups)}' or private IP '{instance_private_ip}'."
    help_text = "\nFor more information see 'Configure an interface endpoint' in https://docs.aws.amazon.com/vpc/latest/privatelink/interface-endpoints.html."
    return "\n".join([error_text, help_text])


def main():
    parser = argparse.ArgumentParser(description="check vpc endpoint for SSM")

    parser.add_argument("--vpc-id", required=True, help="The VPC identifier")
    parser.add_argument("--region", required=True, help="The AWS region")
    parser.add_argument("--security-group-ids", required=True, help="Comma-separated list of security group ids")
    parser.add_argument("--private-ip-address", required=True, help="The instance private ip address")
    args = parser.parse_args()

    ssm_enpoint_name = f"com.amazonaws.{args.region}.ssm"
    instance_security_groups = args.security_group_ids.split(",")
    instance_private_ip = args.private_ip_address
    vpc_id = args.vpc_id

    ssm_vpc_endpoint = get_ssm_vpc_endpoints(vpc_id, ssm_enpoint_name)
    vpce_security_groups: List[str] = []
    vpc_cidr_block = get_vpc_cidr_block(vpc_id)

    print(f"[OK] VPC cidr block '{vpc_cidr_block}'.")

    if ssm_vpc_endpoint:
        vpce_id: str = ssm_vpc_endpoint["VpcEndpointId"]
        vpce_subnets: List[str] = ssm_vpc_endpoint.get("SubnetIds", [])
        vpce_private_dns_enabled: bool = ssm_vpc_endpoint.get("PrivateDnsEnabled", False)
        vpce_enis: List[str] = ssm_vpc_endpoint.get("NetworkInterfaceIds", [])
        vpce_security_group: Dict[str, str]
        for vpce_security_group in ssm_vpc_endpoint.get("Groups", []):
            vpce_security_groups.append(vpce_security_group["GroupId"])

        print(f"[OK] VPC endpoint '{vpce_id}' for Systems Manager found on the EC2 instance's VPC: {vpc_id}.")
        print(f"[OK] Subnets configured for the VPC endpoint found: {', '.join(vpce_subnets)}.")
        if vpce_private_dns_enabled:
            print("[OK] Private DNS is enabled on the VPC endpoint.")
        else:
            print(
                "[WARNING] Private DNS is not enabled on the VPC endpoint (Enabling private DNS names is recommended)."
            )
        print(f"[INFO] Security groups attached to the VPC endpoints: {','.join(vpce_security_groups)}.")

        sgs_validation = validate_segurity_groups(vpce_security_groups, instance_private_ip, instance_security_groups)
        print(sgs_validation)
    else:
        print(f"[INFO] No VPC endpoint for Systems Manager found on the EC2 instance VPC: {vpc_id}.")


if __name__ == "__main__":
    main()