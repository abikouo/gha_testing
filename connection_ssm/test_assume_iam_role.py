#!/usr/bin/env python
# PYTHON_ARGCOMPLETE_OK
"""Terminate or destroy stale resources in the AWS test account."""

import argparse
import contextlib
import os
import argcomplete

import boto3
import botocore
import botocore.client
import botocore.exceptions
from datetime import datetime


@contextlib.contextmanager
def set_env(**kwargs):
    env = os.environ
    update = {}
    for k, v in kwargs.items():
        update.update({k: v})
    try:
        env.update(update)
        yield
    finally:
        # for k, _ in kwargs.items():
        #     env.pop(k)
        pass


def assume_role(
    profile_name, profile_region, role_arn, terminator_region, service_name
):
    session_name = "ansible_testing_" + datetime.now().strftime("%h%m%s")
    params = {"RoleArn": role_arn, "RoleSessionName": session_name}

    # client = boto3.client("sts", profile_name=profile_name, region_name=profile_region)
    client = boto3.client("sts")
    credentials = client.assume_role(**params).get("Credentials")

    return boto3.client(
        service_name,
        region_name=terminator_region,
        aws_access_key_id=credentials.get("AccessKeyId"),
        aws_secret_access_key=credentials.get("SecretAccessKey"),
        aws_session_token=credentials.get("SessionToken"),
    )


def run(regions):
    for region_name in regions:
        print("-----------------------------------------------")
        print(f"-- REGION -- {region_name} ++")
        print("-----------------------------------------------")
        # client = boto3.client("ec2", region_name=region_name)
        # keypairs = client.describe_key_pairs()["KeyPairs"]
        # print(keypairs)
        client = boto3.client("rds", region_name=region_name)
        keypairs = client.describe_db_subnet_groups()["DBSubnetGroups"]
        print(keypairs)


def main():
    args = parse_args()

    for region_name in args.terminator:
        print(f"---------------- REGION ---------------- {region_name} ++")
        # RDS Subnet group
        client = assume_role(
            profile_name=args.profile,
            profile_region=args.region,
            role_arn=args.role_arn,
            terminator_region=region_name,
            service_name="rds",
        )
        for group in client.describe_db_subnet_groups()["DBSubnetGroups"]:
            try:
                client.delete_db_subnet_group(DBSubnetGroupName=group["DBSubnetGroupName"])
                print("[] [] {0} -- DELETED --".format(group["DBSubnetGroupName"]))
            except botocore.exceptions.ClientError as e:
                print("[] [] {0} -- Failure = {1} --".format(group["DBSubnetGroupName"], e))
        # Key Pairs
        client = assume_role(
            profile_name=args.profile,
            profile_region=args.region,
            role_arn=args.role_arn,
            terminator_region=region_name,
            service_name="ec2",
        )
        for key in client.describe_key_pairs()["KeyPairs"]:
            try:
                client.delete_key_pair(KeyName=key["KeyName"])
                print("[] [] [] {0} -- DELETED --".format(key["KeyName"]))
            except botocore.exceptions.ClientError as e:
                print("[] [] [] {0} -- Failure = {1} --".format(key["KeyName"], e))
        # Subnets
        for s in client.describe_subnets()["Subnets"]:
            try:
                client.delete_subnet(SubnetId=s["SubnetId"])
                print("[] [] [] [] {0} -- DELETED --".format(s["SubnetId"]))
            except botocore.exceptions.ClientError as e:
                print("[] [] [] [] {0} -- Failure = {1} --".format(s["SubnetId"], e))
        # VPCs
        for v in client.describe_vpcs()["Vpcs"]:
            try:
                client.delete_vpc(VpcId=v["VpcId"])
                print("[] [] [] [] [] {0} -- DELETED --".format(v["VpcId"]))
            except botocore.exceptions.ClientError as e:
                print("[] [] [] [] [] {0} -- Failure = {1} --".format(v["VpcId"], e))

def parse_args():
    parser = argparse.ArgumentParser(description="Test terminator policy")

    parser.add_argument("--region", required=True, help="AWS account region")

    parser.add_argument("--profile", required=True, help="The AWS profile")

    parser.add_argument("--role-arn", required=True, help="Role ARN")

    parser.add_argument(
        "-t", "--terminator", action="append", required=True, help="Terminator region"
    )

    if argcomplete:
        argcomplete.autocomplete(parser)

    args = parser.parse_args()

    return args


if __name__ == "__main__":
    main()
