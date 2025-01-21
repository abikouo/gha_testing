# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: LicenseRef-.amazon.com.-AmznSL-1.0
# Licensed under the Amazon Software License  http://aws.amazon.com/asl/

import argparse

import boto3
from botocore.exceptions import ClientError
    

def get_instance_public_ip(client, instanceid: str) -> str:
    try:
        result = client.describe_instances(InstanceIds=[instanceid])
        instance = result["Reservations"][0]["Instances"][0]
        public_ip = instance.get("PublicIpAddress", "None")
        return public_ip
    except ClientError as e:
        raise RuntimeError(f"[ERROR] An error occurred while trying to describe the EC2 instance {instanceid} {str(e)}")


def describe_route_tables(client, subnet_id: str, vpc_id: str) -> list:
    try:
        # Get the EC2 instance subnet route table
        result = client.describe_route_tables(Filters=[{"Name": "association.subnet-id", "Values": [subnet_id]}]).get(
            "RouteTables", []
        )

        # If the subnet is not associated with any route table, get the main route table of the VPC.
        if not result:
            result = client.describe_route_tables(
                Filters=[{"Name": "association.main", "Values": ["true"]}, {"Name": "vpc-id", "Values": [vpc_id]}]
            ).get("RouteTables", [])
        return result
    except ClientError as e:
        raise RuntimeError(f"[ERROR] Failed to describe the instance's subnet {subnet_id} route tables {str(e)}")



def main():
    parser = argparse.ArgumentParser(description="check vpc endpoint for SSM")

    parser.add_argument("--vpc-id", required=True, help="The VPC identifier")
    parser.add_argument("--subnet-id", required=True, help="The AWS region")
    parser.add_argument("--instance-id", required=True, help="Comma-separated list of security group ids")
    parser.add_argument("--vpc-endpoint-id", required=False, help="The instance private ip address")
    parser.add_argument("--region", required=False, help="The AWS region", default='us-east-1')

    args = parser.parse_args()

    instance_id = args.instance_id
    subnet_id = args.subnet_id
    vpc_id = args.vpc_id
    vpc_endpoint_id = args.vpc_endpoint_id

    ec2_client = boto3.client("ec2", region_name=args.region)

    public_ip = get_instance_public_ip(ec2_client, instance_id)
    route_tables = describe_route_tables(ec2_client, subnet_id, vpc_id)
    # List of Internet routes (GatewayId, NatGatewayId, TransitGatewayId, NetworkInterfaceId, VpcPeeringConnectionId)
    internet_route_list = []
    # List of local (default) routes
    cidr_for_local_list = []

    for route_table in route_tables:
        route_table_id = route_table["RouteTableId"]
        print(f"[INFO] VPC route table found: {route_table_id}.")
        routes = route_table["Routes"]

        for route_entry in routes:
            for element_id in [
                "GatewayId",
                "NatGatewayId",
                "TransitGatewayId",
                "NetworkInterfaceId",
                "VpcPeeringConnectionId",
            ]:
                if (
                    element_id in route_entry
                    and "DestinationCidrBlock" in route_entry
                    and route_entry["DestinationCidrBlock"] == "0.0.0.0/0"
                ):
                    # Add Internet route
                    internet_route = route_entry[element_id]
                    status = route_entry.get("State", "active")
                    internet_route_list.append((internet_route, status))

            # Local Route
            if (
                "GatewayId" in route_entry
                and "DestinationIpv6CidrBlock" not in route_entry
                and route_entry["GatewayId"] == "local"
            ):
                # Add local (default) route
                cidr_for_local_list.append(route_entry["DestinationCidrBlock"])

    # Check if local route (default route) is used to communicate with the VPC SSM interface endpoint.
    if cidr_for_local_list:
        print(f"[INFO] VPC local route (default route) available for {', '.join(cidr_for_local_list)}.")
        if vpc_endpoint_id:
            print(
                f"[OK] The local route (default route) is used to communicate with the Systems Manager VPC endpoint interface '{vpc_endpoint_id}'."
            )
        else:
            print("[WARNING] A local route is required to communicate with the VPC endpoint interface.")

    # Check if internet route is used to communicate with the SSM endpoint.
    if not internet_route_list:
        if vpc_endpoint_id:  # If the VPC has a Systems Manager VPC endpoint interface
            print(
                f"[OK] A public route is not required to communicate with the Systems Manager VPC endpoint interface '{vpc_endpoint_id}'."
            )
        else:  # If no VPC endpoint interface is present, a public route is required
            print(
                "[WARNING] No route found for 0.0.0.0/0. Internet access is required to connect to the public Systems Manager endpoint."
            )

    else:
        # Loop through the internet routes an add information that can be used for troubleshooting connectivity.
        for item, state in internet_route_list:
            print(f"[INFO] VPC Internet route with destination 0.0.0.0/0 found with target '{item}'.")

            if state != "active":
                print(f"[WARNING] VPC Internet route and is marked as '{state}'.")
            else:
                if "igw" in item:
                    if public_ip == "None":
                        print(
                            f"[WARNING] VPC internet gateway '{item}' route associated, however the instance does not have a public IP address associated. Internet connectivity through the internet gateway is unavailable."
                        )
                    else:
                        print(
                            f"[OK] VPC internet gateway '{item}' route associated and the instance has a public IP address ({public_ip}) associated."
                        )

                if "nat" in route_table:
                    print(
                        f"[OK] VPC NAT gateway '{item}' present. Make sure the NAT gateway allow access to the Systems Manager endpoints."
                    )

                if "eni-" in route_table:
                    print(
                        f"[INFO] Network interface '{item}' route associated. All traffic is automatically routed to this interface. Make sure the node associated with this network interface allow access to the Systems Manager endpoints."
                    )

                if "vgw" in route_table:
                    print(
                        f"[INFO] Virtual private gateway '{item}' route associated. Make sure the VPN connection allow access to the Systems Manager endpoints."
                    )

                if "tgw" in route_table:
                    print(
                        f"[INFO] Transit gateway '{item}' route associated. Make sure the Transit gateway routes are configured to allow access to the Systems Manager endpoints."
                    )

                if "pcx" in route_table:
                    print(
                        f"[INFO] VPC peering connection '{item}' route associated. Make sure the VPC peering connection allows access to the Systems Manager endpoints."
                    )

                if "vpce" in route_table:
                    print(
                        f"[INFO] VPCe gateway load balancer '{item}' route associated. Make sure the VPCe gateway load balancer allows access to the Systems Manager endpoints."
                    )

if __name__ == "__main__":
    main()