# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: LicenseRef-.amazon.com.-AmznSL-1.0
# Licensed under the Amazon Software License  http://aws.amazon.com/asl/

import argparse

import boto3
from botocore.exceptions import ClientError
import ipaddress
from ipaddress import ip_network
from typing import Dict, List


class InstanceProperties:

    def __init__(self, client, instance_id) -> None:
        self._instance_id = instance_id
        self._instance_info = None
        self._client = client
    
    @property
    def client(self):
        return self._client

    @property
    def instance_info(self):
        if self._instance_info is None:
            self._instance_info = self._client.describe_instances(InstanceIds=[self._instance_id])["Reservations"][0]["Instances"][0]
        return self._instance_info

    @property
    def instance_id(self):
        return self._instance_id

    @property
    def security_group_ids(self):
        return [g["GroupId"] for g in self.instance_info.get("SecurityGroups")]

    @property
    def subnet_id(self):
        return self.instance_info.get("SubnetId")

    @property
    def vpc_id(self):
        return self.instance_info.get("VpcId")

    @property
    def private_ip_address(self):
        return self.instance_info["NetworkInterfaces"][0]["PrivateIpAddresses"][0]["PrivateIpAddress"]

    @property
    def instance_profile(self):
        return self.instance_info.get("IamInstanceProfile", {}).get("Arn")



class checkVpcEndpoint:

    def __init__(self, instance_property, region) -> None:

        self.vpcEndpointId = None
        self.vpcEndpointSubnets = None
        self.vpcEndpointEnis = None
        self.vpc_endpoint_security_group_ids = None
        self.vpc_cidr_block = None

        ssm_enpoint_name = f"com.amazonaws.{region}.ssm"

        instance_security_groups: List[str] = instance_property.security_group_ids
        instance_private_ip: str = instance_property.private_ip_address
        vpc_id: str = instance_property.vpc_id

        ssm_vpc_endpoint = self.get_ssm_vpc_endpoints(instance_property.client, vpc_id, ssm_enpoint_name)
        vpce_security_groups: List[str] = []
        vpc_cidr_block = self.get_vpc_cidr_block(instance_property.client, vpc_id)

        if ssm_vpc_endpoint:
            vpce_id: str = ssm_vpc_endpoint["VpcEndpointId"]
            vpce_subnets: List[str] = ssm_vpc_endpoint.get("SubnetIds", [])
            vpce_private_dns_enabled: bool = ssm_vpc_endpoint.get("PrivateDnsEnabled", False)
            vpce_enis: List[str] = ssm_vpc_endpoint.get("NetworkInterfaceIds", [])
            vpce_security_group: Dict[str, str]
            for vpce_security_group in ssm_vpc_endpoint.get("Groups", []):
                vpce_security_groups.append(vpce_security_group["GroupId"])

            print(f"--- checkVpcEndpoint --- [OK] VPC endpoint '{vpce_id}' for Systems Manager found on the EC2 instance's VPC: {vpc_id}.")
            print(f"--- checkVpcEndpoint --- [OK] Subnets configured for the VPC endpoint found: {', '.join(vpce_subnets)}.")
            if vpce_private_dns_enabled:
                print("--- checkVpcEndpoint --- [OK] Private DNS is enabled on the VPC endpoint.")
            else:
                print(
                    "--- checkVpcEndpoint --- [WARNING] Private DNS is not enabled on the VPC endpoint (Enabling private DNS names is recommended)."
                )
            print(f"--- checkVpcEndpoint --- [INFO] Security groups attached to the VPC endpoints: {','.join(vpce_security_groups)}.")

            sgs_validation = self.validate_segurity_groups(instance_property.client, vpce_security_groups, instance_private_ip, instance_security_groups)
            print(sgs_validation)
            self.VpcEndpointId = vpce_id
            self.VpcEndpointSubnets = vpce_subnets
            self.VpcEndpointEnis = vpce_enis
            self.VpcEndpointSecurityGroupIds = vpce_security_groups
            self.VpcCidrBlock = vpc_cidr_block
        else:
            print(f"--- checkVpcEndpoint --- [INFO] No VPC endpoint for Systems Manager found on the EC2 instance VPC: {vpc_id}.")
            self.VpcEndpointId = ""
            self.VpcEndpointSubnets = []
            self.VpcEndpointEnis = []
            self.VpcEndpointSecurityGroupIds = []
            self.VpcCidrBlock = vpc_cidr_block


    def get_vpc_cidr_block(self, ec2_client, vpc_id) -> str:
        try:
            response = ec2_client.describe_vpcs(VpcIds=[vpc_id])
        except ClientError as e:
            raise RuntimeError(f"--- checkVpcEndpoint --- [ERROR] An error occurred while trying to describe the VPC {vpc_id}: {str(e)}") from None

        return response.get("Vpcs", [])[0].get("CidrBlock")

    def get_ssm_vpc_endpoints(self, ec2_client, vpc_id, ssm_enpoint_name) -> dict:
        try:
            response = ec2_client.describe_vpc_endpoints(
                Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "service-name", "Values": [ssm_enpoint_name]}]
            )
        except ClientError as e:
            raise RuntimeError(
                f"--- checkVpcEndpoint --- [ERROR] An error occurred while trying to describe the VPC endpoint {ssm_enpoint_name} for {vpc_id}: {str(e)}"
            ) from None

        ssm_endpoints = response.get("VpcEndpoints", [])
        for endpoint in ssm_endpoints:
            if endpoint["State"].lower() == "available":
                return endpoint
            else:
                print(f"--- checkVpcEndpoint --- [WARNING] VPC endpoint '{endpoint['VpcEndpointId']}' is not in 'Available' state.")
                return {}
        else:
            return {}

    def validate_segurity_groups(self, ec2_client, vpce_security_groups, instance_private_ip, instance_security_groups) -> str:
        https_port = 443
        for vpce_security_group in vpce_security_groups:
            try:
                response = ec2_client.describe_security_groups(GroupIds=[vpce_security_group])
            except ClientError as e:
                raise RuntimeError(
                    f"--- checkVpcEndpoint --- [ERROR] An error occurred while trying to describe the security group {vpce_security_group}: {str(e)}"
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
                                return f"--- checkVpcEndpoint --- [OK] VPC endpoint security group '{vpce_security_group}' allows traffic on port '{https_port}' from the instance private IP '{instance_private_ip}'."

                        for group in rule.get("UserIdGroupPairs", []):
                            for security_group_id in instance_security_groups:
                                if security_group_id in group["GroupId"]:
                                    return f"--- checkVpcEndpoint --- [OK] VPC endpoint security group '{vpce_security_group}' allows traffic on port {https_port} from the instance security group {security_group_id}."

        # If we reach this point, it means that the security group does not allow traffic from the instance.
        error_text = f"--- checkVpcEndpoint --- [ERROR] VPC endpoint security groups '{', '.join(vpce_security_groups)}' do not allow traffic on port '{https_port}' from the instance security group(s) '{', '.join(instance_security_groups)}' or private IP '{instance_private_ip}'."
        help_text = "\nFor more information see 'Configure an interface endpoint' in https://docs.aws.amazon.com/vpc/latest/privatelink/interface-endpoints.html."
        return "\n".join([error_text, help_text])


class checkRouteTable:

    def __init__(self, client,  instance_id, subnet_id, vpc_id, vpc_endpoint_id):

        self._instance_id = instance_id
        self._subnet_id = subnet_id
        self._vpc_id = vpc_id

        public_ip = self.get_instance_public_ip(client)
        route_tables = self.describe_route_tables(client)

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
            print(f"--- checkRouteTable --- [INFO] VPC local route (default route) available for {', '.join(cidr_for_local_list)}.")
            if vpc_endpoint_id:
                print(
                    f"--- checkRouteTable --- [OK] The local route (default route) is used to communicate with the Systems Manager VPC endpoint interface '{vpc_endpoint_id}'."
                )
            else:
                print("--- checkRouteTable --- [WARNING] A local route is required to communicate with the VPC endpoint interface.")

        # Check if internet route is used to communicate with the SSM endpoint.
        if not internet_route_list:
            if vpc_endpoint_id:  # If the VPC has a Systems Manager VPC endpoint interface
                print(
                    f"[OK] A public route is not required to communicate with the Systems Manager VPC endpoint interface '{vpc_endpoint_id}'."
                )
            else:  # If no VPC endpoint interface is present, a public route is required
                print(
                    "--- checkRouteTable --- [WARNING] No route found for 0.0.0.0/0. Internet access is required to connect to the public Systems Manager endpoint."
                )

        else:
            # Loop through the internet routes an add information that can be used for troubleshooting connectivity.
            for item, state in internet_route_list:
                print(f"--- checkRouteTable --- [INFO] VPC Internet route with destination 0.0.0.0/0 found with target '{item}'.")

                if state != "active":
                    print(f"--- checkRouteTable --- [WARNING] VPC Internet route and is marked as '{state}'.")
                else:
                    if "igw" in item:
                        if public_ip == "None":
                            print(
                                f"--- checkRouteTable --- [WARNING] VPC internet gateway '{item}' route associated, however the instance does not have a public IP address associated. Internet connectivity through the internet gateway is unavailable."
                            )
                        else:
                            print(
                                f"--- checkRouteTable --- [OK] VPC internet gateway '{item}' route associated and the instance has a public IP address ({public_ip}) associated."
                            )

                    if "nat" in route_table:
                        print(
                            f"--- checkRouteTable --- [OK] VPC NAT gateway '{item}' present. Make sure the NAT gateway allow access to the Systems Manager endpoints."
                        )

                    if "eni-" in route_table:
                        print(
                            f"--- checkRouteTable --- [INFO] Network interface '{item}' route associated. All traffic is automatically routed to this interface. Make sure the node associated with this network interface allow access to the Systems Manager endpoints."
                        )

                    if "vgw" in route_table:
                        print(
                            f"--- checkRouteTable --- [INFO] Virtual private gateway '{item}' route associated. Make sure the VPN connection allow access to the Systems Manager endpoints."
                        )

                    if "tgw" in route_table:
                        print(
                            f"--- checkRouteTable --- [INFO] Transit gateway '{item}' route associated. Make sure the Transit gateway routes are configured to allow access to the Systems Manager endpoints."
                        )

                    if "pcx" in route_table:
                        print(
                            f"--- checkRouteTable --- [INFO] VPC peering connection '{item}' route associated. Make sure the VPC peering connection allows access to the Systems Manager endpoints."
                        )

                    if "vpce" in route_table:
                        print(
                            f"--- checkRouteTable --- [INFO] VPCe gateway load balancer '{item}' route associated. Make sure the VPCe gateway load balancer allows access to the Systems Manager endpoints."
                        )


    def get_instance_public_ip(self, client) -> str:
        try:
            result = client.describe_instances(InstanceIds=[self._instance_id])
            instance = result["Reservations"][0]["Instances"][0]
            public_ip = instance.get("PublicIpAddress", "None")
            return public_ip
        except ClientError as e:
            raise RuntimeError(f"--- checkRouteTable --- [ERROR] An error occurred while trying to describe the EC2 instance {self._instance_id} {str(e)}")

    def describe_route_tables(self, client) -> list:
        try:
            # Get the EC2 instance subnet route table
            result = client.describe_route_tables(Filters=[{"Name": "association.subnet-id", "Values": [self._subnet_id]}]).get(
                "RouteTables", []
            )

            # If the subnet is not associated with any route table, get the main route table of the VPC.
            if not result:
                result = client.describe_route_tables(
                    Filters=[{"Name": "association.main", "Values": ["true"]}, {"Name": "vpc-id", "Values": [self._vpc_id]}]
                ).get("RouteTables", [])
            return result
        except ClientError as e:
            raise RuntimeError(f"--- checkRouteTable --- [ERROR] Failed to describe the instance's subnet {self._subnet_id} route tables {str(e)}")


class checkNacl:

    def __init__(self, ec2_client, instance_id, subnet_id, vpc_endpoint_id, instance_private_ip, vpc_endpoint_subnets):

        result = []
        if vpc_endpoint_id and subnet_id in vpc_endpoint_subnets:
            print(
                "--- checkNACL --- [SKIPPED] VPC endpoint for Systems Manager is present and in the same subnet as the EC2 instance."
            )
            return {"Message": "\n- ".join(result)}

        # Check requirements for instance's network ACL (ephemeral ports outbound)
        print(f"--- checkNACL --- Check network ACLs requirements instance '{instance_id}' for instance subnet '{subnet_id}':")
        ephemeral_ports_outbound = {"-1": [[1024, 65535]]}
        instance_reqs = self.check_nacl_traffic_requirements(ec2_client, subnet_id, instance_private_ip, False, ephemeral_ports_outbound)
        result.extend(instance_reqs)

        if vpc_endpoint_id:
            for vpce_subnet_id in vpc_endpoint_subnets:
                # Check requirements for VPC endpoint's network ACL (ephemeral ports outbound)
                print(
                    f"--- checkNACL --- Check network ACLs requirements for the VPC endpoint '{vpc_endpoint_id}' subnet '{vpce_subnet_id}':"
                )
                ephemeral_ports_outbound = {"-1": [[1024, 65535]]}
                vpce_reqs = self.check_nacl_traffic_requirements(ec2_client, vpce_subnet_id, "0.0.0.0/0", False, ephemeral_ports_outbound)
                result.extend(vpce_reqs)
                https_inbound = {"tcp": [[443, 443]]}
                vpce_reqs = self.check_nacl_traffic_requirements(ec2_client, vpce_subnet_id, instance_private_ip, True, https_inbound)
                result.extend(vpce_reqs)


    @staticmethod
    def describe_network_acls(ec2_client, subnet_id):
        """Analyse Network ACL rules for all traffic open from '0.0.0.0/0"""
        try:
            response = ec2_client.describe_network_acls(Filters=[{"Name": "association.subnet-id", "Values": [subnet_id]}])
            network_acls = response.get("NetworkAcls")[0].get("Entries", [])
            network_acl_id = response.get("NetworkAcls")[0].get("NetworkAclId")
            return network_acl_id, network_acls

        except ClientError as error:
            raise RuntimeError(
                f"--- checkNACL --- [ERROR] Failed to describe the instance's Network ACLs from subnet {subnet_id}: {str(error)}."
            )
    
    @staticmethod
    def check_allowed(allowed_traffic, source, required_traffic, is_inbound):
        rules = allowed_traffic[source]
        result = []
        # Loop through the required traffic and check if it is allowed. If it is not allowed, add an error to the result.
        # allowed_traffic: {"0.0.0.0/0": {"-1": [[0, 65535]]}, "10.0.57.3": {"-1": [[0, 65535]], "udp: [[53,53],[10,123]]}}
        # required_traffic: {"tcp": [[442, 443]], "udp: [[53,53],[10,123]]"}
        for required_protocol, required_ranges in required_traffic.items():
            str_protocol = required_protocol.replace("-1", "all").upper()
            for required_range in required_ranges:
                allowed = False

                # Loop through the allowed traffic and check if it is allowed. If it is not allowed, add an error to the result.
                for allowed_protocol, allowed_ranges in rules.items():
                    for allowed_range in allowed_ranges:
                        required_range_set = set(range(required_range[0], required_range[1] + 1))
                        allowed_range_set = set(range(allowed_range[0], allowed_range[1] + 1))
                        if (
                            allowed_protocol in ("-1", required_protocol)  # "-1" matches all protocols
                            and required_range_set
                            and allowed_range_set
                            and required_range_set.issubset(allowed_range_set)
                        ):
                            if is_inbound:
                                print(
                                    f"--- checkNACL --- [OK] '{str_protocol}' inbound traffic allowed from '{source}' to '{required_range}'"
                                )
                            else:
                                print(
                                    f"--- checkNACL --- [OK] '{str_protocol}' outbound traffic allowed to '{source}' from '{required_range}'"
                                )
                            allowed = True
                            break
                if not allowed:
                    if is_inbound:
                        print(
                            f"--- checkNACL --- [ERROR] '{str_protocol}' inbound traffic not allowed from '{source}' to '{required_range}'"
                        )
                    else:
                        print(
                            f"--- checkNACL --- [ERROR] '{str_protocol}' outbound traffic not allowed to '{source}' from '{required_range}'"
                        )
                else:
                    break
        return result

    @staticmethod
    def get_std_protocol(acl_protocol):
        # defined at https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
        customprotocol = {
            "-1": "-1",
            "hopopt": "0",
            "icmp": "1",
            "igmp": "2",
            "ggp": "3",
            "ipv4": "4",
            "st": "5",
            "tcp": "6",
            "cbt": "7",
            "egp": "8",
            "igp": "9",
            "bbn-rcc-mon": "10",
            "nvp-ii": "11",
            "pup": "12",
            "argus": "13",
            "emcon": "14",
            "xnet": "15",
            "chaos": "16",
            "udp": "17",
            "mux": "18",
            "dcn-meas": "19",
            "hmp": "20",
            "prm": "21",
            "xns-idp": "22",
            "trunk-1": "23",
            "trunk-2": "24",
            "leaf-1": "25",
            "leaf-2": "26",
            "rdp": "27",
            "irtp": "28",
            "iso-tp4": "29",
            "netblt": "30",
            "mfe-nsp": "31",
            "merit-inp": "32",
            "dccp": "33",
            "3pc": "34",
            "idpr": "35",
            "xtp": "36",
            "ddp": "37",
            "idpr-cmtp": "38",
            "tp++": "39",
            "il": "40",
            "ipv6": "41",
            "sdrp": "42",
            "ipv6-route": "43",
            "ipv6-frag": "44",
            "idrp": "45",
            "rsvp": "46",
            "gre": "47",
            "dsr": "48",
            "bna": "49",
            "esp": "50",
            "ah": "51",
            "i-nlsp": "52",
            "swipe": "53",
            "narp": "54",
            "mobile": "55",
            "tlsp": "56",
            "ipv6-icmp": "58",
            "ipv6-nonxt": "59",
            "ipv6-opts": "60",
            "61": "61",
            "cftp": "62",
            "63": "63",
            "sat-expak": "64",
            "kryptolan": "65",
            "rvd": "66",
            "ippc": "67",
            "68": "68",
            "sat-mon": "69",
            "visa": "70",
            "ipcv": "71",
            "cpnx": "72",
            "cphb": "73",
            "wsn": "74",
            "pvp": "75",
            "br-sat-mon": "76",
            "sun-nd": "77",
            "wb-mon": "78",
            "wb-expak": "79",
            "iso-ip": "80",
            "vmtp": "81",
            "secure-vmtp": "82",
            "vines": "83",
            "ttp": "84",
            "nsfnet-igp": "85",
            "dgp": "86",
            "tcf": "87",
            "eigrp": "88",
            "ospfigp": "89",
            "sprite-rpc": "90",
            "larp": "91",
            "mtp": "92",
            "ax.25": "93",
            "ipip": "94",
            "micp": "95",
            "scc-sp": "96",
            "etherip": "97",
            "encap": "98",
            "99": "99",
            "gmtp": "100",
            "ifmp": "101",
            "pnni": "102",
            "pim": "103",
            "aris": "104",
            "scps": "105",
            "qnx": "106",
            "a/n": "107",
            "ipcomp": "108",
            "snp": "109",
            "compaq-peer": "110",
            "ipx-in-ip": "111",
            "vrrp": "112",
            "pgm": "113",
            "114": "114",
            "l2tp": "115",
            "dd": "116",
            "iatp": "117",
            "stp": "118",
            "srp": "119",
            "uti": "120",
            "smp": "121",
            "sm": "122",
            "ptp": "123",
            "isis-over-ipv4": "124",
            "fire": "125",
            "crtp": "126",
            "crudp": "127",
            "sscopmce": "128",
            "iplt": "129",
            "sps": "130",
            "pipe": "131",
            "sctp": "132",
            "fc": "133",
            "rsvp-e2e-ignore": "134",
            "mobility-header": "135",
            "udplite": "136",
            "mpls-in-ip": "137",
            "manet": "138",
            "hip": "139",
            "shim6": "140",
            "wesp": "141",
            "rohc": "142",
            "253": "253",
            "254": "254",
        }
        inv_map = {v: k for k, v in customprotocol.items()}
        return inv_map.get(acl_protocol)

    @staticmethod
    def range_add(new_port_range, interv):
        # if new not in interv:
        interv.append(new_port_range)
        interv = [
            port_range
            for port_range in interv
            if port_range != [] and len(port_range) == 2 and all(isinstance(val, int) for val in port_range)
        ]
        interv.sort()

        new_interval = []
        while len(interv) > 0:
            if len(interv) == 1:
                new_interval.append(interv[0])
                interv.pop(0)
                continue
            if interv[0][1] >= interv[1][0]:
                tmp = [interv[0][0], max(interv[0][1], interv[1][1])]
                interv[0] = tmp
                interv.pop(1)
                continue

            new_interval.append(interv[0])
            interv.pop(0)
        return new_interval

    @staticmethod
    def range_diff(new_range, interv):
        interv = checkNacl.range_add([], interv)
        if len(new_range) == 0:
            new_range = [0, 0]
        interv = [
            port_range
            for port_range in interv
            if port_range != [] and len(port_range) == 2 and all(isinstance(val, int) for val in port_range)
        ]
        interv.sort()
        new_interval = []
        for port_range in interv:
            from_port, to_port = port_range
            from_port_new, to_port_new = new_range
            sorted_ports = sorted((from_port, from_port_new, to_port, to_port_new))
            if sorted_ports[0] == from_port and sorted_ports[0] != sorted_ports[1]:
                min_port = sorted_ports[1] if to_port < from_port_new else sorted_ports[1] - 1
                new_interval.append([sorted_ports[0], min_port])
            if sorted_ports[3] == to_port and sorted_ports[2] != sorted_ports[3]:
                min_port = sorted_ports[2] if to_port_new < from_port else sorted_ports[2] + 1
                new_interval.append([min_port, sorted_ports[3]])
        if len(new_interval) == 0:
            new_interval = [[0, 0]]
        return new_interval

    @staticmethod
    def eval_acl_rules(entries, source):
        from ipaddress import ip_network

        allows_in: Dict[str, Dict[str, List[List[int]]]] = {}
        allows_out: Dict[str, Dict[str, List[List[int]]]] = {}

        try:
            for network_cidr in source:
                in_allow: Dict[str, List[List[int]]] = {}
                out_allow: Dict[str, List[List[int]]] = {}
                for rule in sorted(entries, key=lambda k: k["RuleNumber"], reverse=True):
                    if rule.get("Ipv6CidrBlock") and not rule.get("CidrBlock"):  # Skip IpV6 rules
                        continue
                    protocol = checkNacl.get_std_protocol(rule["Protocol"])
                    network_in_acl = ip_network(rule["CidrBlock"], strict=False)
                    network_in_source = ip_network(network_cidr, strict=False)

                    if "PortRange" not in rule:
                        from_port = 0
                        to_port = 65535
                    else:
                        from_port = rule["PortRange"]["From"]
                        to_port = rule["PortRange"]["To"]

                    if not rule["Egress"]:
                        if rule["RuleAction"] == "allow":
                            if network_in_source.subnet_of(network_in_acl):  # type: ignore
                                in_allow[protocol] = checkNacl.range_add([from_port, to_port], in_allow.get(protocol, []))
                        else:
                            if network_in_source.subnet_of(network_in_acl):  # type: ignore
                                in_allow[protocol] = checkNacl.range_diff([from_port, to_port], in_allow.get(protocol, []))

                    else:
                        if rule["RuleAction"] == "allow":
                            if network_in_source.subnet_of(network_in_acl):  # type: ignore
                                out_allow[protocol] = checkNacl.range_add([from_port, to_port], out_allow.get(protocol, []))
                        else:
                            if network_in_source.subnet_of(network_in_acl):  # type: ignore
                                out_allow[protocol] = checkNacl.range_diff([from_port, to_port], out_allow.get(protocol, []))

                allows_in[network_cidr] = dict(in_allow)
                allows_out[network_cidr] = dict(out_allow)

            return dict(allows_in), dict(allows_out)

        except Exception as e:
            raise ValueError("Failed to evaluate Network ACLs.", str(e))

    @staticmethod
    def check_nacl_traffic_requirements(ec2_client, subnet_id, source, is_inbound, required_traffic):
        network_acl_id, nacls = checkNacl.describe_network_acls(ec2_client, subnet_id)
        result = [f"--- checkNACL --- Check network ACLs requirements on network ACL '{network_acl_id}':"]
        # Eval allowed inbound and outbound traffic from/to 0.0.0.0 and the instance private IP
        inbound, outbound = checkNacl.eval_acl_rules(nacls, [source])

        if is_inbound:
            # Check if the required inbound traffic.
            allowed_result = checkNacl.check_allowed(inbound, source, required_traffic, is_inbound)
            result.extend(allowed_result)
        else:
            allowed_result = checkNacl.check_allowed(outbound, source, required_traffic, is_inbound)
            result.extend(allowed_result)

        return result


class HelperBase:
    def __init__(self, client, vpc_endpoint_enis, instance_security_groups):
        self.vpc_endpoint_enis = vpc_endpoint_enis
        self.instance_security_groups = instance_security_groups
        self.vpc_endpoint_ip_addresses = []
        self.instance_security_group_details = []
        self.group_label = None
        self.verb = None
        self.ec2_client = client

    def fetch_vpc_endpoint_ips(self):
        """
        Fetch the private IP addresses of the VPC endpoint.

        Raises:
            RuntimeError: If an error occurs while trying to describe the network interfaces.
        """
        try:
            response = self.ec2_client.describe_network_interfaces(NetworkInterfaceIds=self.vpc_endpoint_enis)
        except ClientError as e:
            raise RuntimeError(
                f"--- checkInstanceSecurityGroup --- [ERROR] An error occurred while trying to describe the network interfaces {', '.join(self.vpc_endpoint_enis)}: {str(e)}"
            ) from None

        self.vpc_endpoint_ip_addresses = [eni.get("PrivateIpAddress") for eni in response.get("NetworkInterfaces", [])]

    def fetch_instance_security_group_details(self):
        """
        Fetch the details of the instance security groups.

        Raises:
            RuntimeError: If an error occurs while trying to describe the security groups.
        """
        try:
            response = self.ec2_client.describe_security_groups(GroupIds=self.instance_security_groups)
        except ClientError as e:
            raise RuntimeError(
                f"--- checkInstanceSecurityGroup --- [ERROR] An error occurred while trying to describe the security group {', '.join(self.instance_security_groups)}: {str(e)}"
            ) from None

        self.instance_security_group_details = response.get("SecurityGroups", [])

    def correct_verbiage(self, groups, sentiment="negative"):
        self.group_label = "groups" if len(groups) > 1 else "group"
        if sentiment == "positive":
            self.verb = "allow" if len(groups) > 1 else "allows"
        else:
            self.verb = "do not allow" if len(groups) > 1 else "does not allow"


class SecurityGroupEvaluator(HelperBase):
    def __init__(self, client, instance_id, vpc_endpoint_id, security_group_ids, vpc_endpoint_security_group_ids, vpc_endpoint_enis):
        super().__init__(client, vpc_endpoint_enis, security_group_ids)
        self.https_port = 443
        self.instance_id = instance_id
        self.vpc_endpoint_id = vpc_endpoint_id
        self.vpc_endpoint_security_groups = vpc_endpoint_security_group_ids
        self.allowed_sgs = []
        self.rule_access_allowed = False
        self.result = []

    def __call__(self):
        """
        Evaluate the security group rules for the instance and VPC endpoint.

        Returns:
            list: A list of strings representing the evaluation results.
        """
        self.fetch_vpc_endpoint_ips()
        self.fetch_instance_security_group_details()

        self.result.append("--- checkInstanceSecurityGroup --- Check outbound traffic to the public Systems Manager endpoint:")
        self.evaluate_rules(["0.0.0.0/0"], self.evaluate_ip_destination)
        if any(message.startswith("[OK]") for message in self.result):
            return self.result

        if self.vpc_endpoint_id:
            self.result.append(
                f"--- checkInstanceSecurityGroup --- Check outbound traffic to the Systems Manager VPC interface endpoint '{self.vpc_endpoint_id}':"
            )

            self.result.append(
                f"--- checkInstanceSecurityGroup --- Check outbound traffic to endpoint security groups {', '.join(self.vpc_endpoint_security_groups)}:"
            )
            self.evaluate_rules(self.vpc_endpoint_security_groups, self.evaluate_sg_destination)

            self.result.append(
                f"--- checkInstanceSecurityGroup --- Check outbound traffic to the endpoint IP addresses {', '.join(self.vpc_endpoint_ip_addresses)}:"
            )
            self.evaluate_rules(self.vpc_endpoint_ip_addresses, self.evaluate_ip_destination)

        if not any(message.startswith("[OK]") for message in self.result):
            self.correct_verbiage(self.instance_security_groups)
            self.result.append(
                f"--- checkInstanceSecurityGroup --- [ERROR] Instance security {self.group_label} '{', '.join(self.instance_security_groups)}' {self.verb} outbound traffic on port '{self.https_port}'."
            )

        print("\n".join(self.result))

    def evaluate_rules(self, destinations, evaluate_destination):
        """
        Evaluate the security group rules for the instance and VPC endpoint.

        Args:
            destinations (list): A list of destination IP addresses or security group IDs.
            evaluate_destination (function): A function to evaluate the destination against the security group rules.
        """
        self.allowed_sgs = []
        for destination in destinations:
            for security_group in self.instance_security_group_details:
                group_id = security_group["GroupId"]
                for rule in security_group.get("IpPermissionsEgress", []):
                    self.rule_access_allowed = False
                    if (
                        (rule.get("IpProtocol") == "-1")
                        or (rule.get("FromPort") == -1 and rule.get("ToPort") == -1)
                        or (self.https_port in range(rule.get("FromPort"), rule.get("ToPort") + 1))
                    ):
                        evaluate_destination(rule, destination, group_id)
                    if self.rule_access_allowed:
                        break
                else:
                    self.result.append(
                        f"--- checkInstanceSecurityGroup --- [INFO] Instance security group '{group_id}' does not allow outbound traffic on port '{self.https_port}' to '{destination}'."
                    )

        self.generate_ok_warning_message(destinations)

    def evaluate_ip_destination(self, rule, destination, group_id):
        """
        Evaluate if the destination IP address is within the CIDR range of the source IP address.

        Args:
            rule (dict): A dictionary representing the security group rule.
            destination (str): The destination IP address or CIDR block.
            group_id (str): The ID of the security group.
        """
        destination_network = ip_network(destination, strict=False)
        for cidr in rule.get("IpRanges", []):
            source_network = ip_network(cidr["CidrIp"], strict=False)
            if destination_network.subnet_of(source_network):  # type: ignore
                self.result.append(
                    f"--- checkInstanceSecurityGroup --- [INFO] Instance security group '{group_id}' allows outbound traffic on port '{self.https_port}' to '{destination}'."
                )
                if group_id not in self.allowed_sgs:
                    self.allowed_sgs.append(group_id)
                self.rule_access_allowed = True
                break

    def evaluate_sg_destination(self, rule, destination, group_id):
        """
        Evaluate if the destination security group ID is in the list of source security groups.

        Args:
            rule (dict): A dictionary representing the security group rule.
            destination (str): The destination security group ID.
            group_id (str): The ID of the security group.
        """
        for group in rule.get("UserIdGroupPairs", []):
            if destination in group["GroupId"]:
                self.result.append(
                    f"--- checkInstanceSecurityGroup --- [INFO] Instance security group '{group_id}' allows outbound traffic on port '{self.https_port}' to '{destination}'."
                )
                if group_id not in self.allowed_sgs:
                    self.allowed_sgs.append(group_id)
                self.rule_access_allowed = True
                break

    def generate_ok_warning_message(self, destinations):
        """
        Generate an OK or WARNING message based on the allowed security groups or IP addresses.

        Args:
            destinations (list): A list of destination IP addresses or security group IDs.
        """
        if "0.0.0.0/0" in destinations:
            if self.vpc_endpoint_id:
                destination_label = "'0.0.0.0/0'"
            else:
                destination_label = "public System Manager endpoint"
        elif destinations[0].startswith("sg-"):
            destination_label = "endpoint security groups"
        else:
            destination_label = "endpoint IP addresses"

        if self.allowed_sgs:
            self.correct_verbiage(self.allowed_sgs, "positive")
            self.result.append(
                f"--- checkInstanceSecurityGroup --- [OK] Instance security {self.group_label} '{', '.join(self.allowed_sgs)}' {self.verb} outbound traffic on port '{self.https_port}' to {destination_label}."
            )
        else:
            self.correct_verbiage(self.instance_security_groups)
            self.result.append(
                f"--- checkInstanceSecurityGroup --- [WARNING] Instance security {self.group_label} '{', '.join(self.instance_security_groups)}' {self.verb} outbound traffic on port '{self.https_port}' to {destination_label}."
            )


def check_required_managed_policies(managed_policies):
    managed_policies_list = [
        "AmazonSSMManagedInstanceCore",
        "AmazonSSMFullAccess",
        "AdministratorAccess",
        "AmazonEC2RoleforSSM",
        "AmazonSSMManagedEC2InstanceDefaultPolicy",
    ]
    for policy in managed_policies:
        if policy["PolicyName"] in managed_policies_list:
            return True
    return False


def get_instance_profile(ec2_client, instance_id):
    try:
        response = ec2_client.describe_instances(InstanceIds=[instance_id])
        instance_profile = response["Reservations"][0]["Instances"][0].get("IamInstanceProfile")
        if instance_profile:
            return instance_profile["Arn"].split("/")[-1]
        else:
            return ""
    except ClientError as e:
        raise RuntimeError(f"--- checkInstanceIAM --- [ERROR] Failed todescribe the EC2 instance {instance_id}: {str(e)}") from None


def get_attached_managed_policies(iam_client, role_name):
    try:
        response = iam_client.list_attached_role_policies(RoleName=role_name)
        return response.get("AttachedPolicies", [])
    except ClientError as e:
        raise RuntimeError(f"--- checkInstanceIAM --- [ERROR] Failed to list attached managed policies for {role_name}: {str(e)}")


def get_iam_role_from_profile_name(iam_client, instance_profile_name):
    try:
        response = iam_client.get_instance_profile(InstanceProfileName=instance_profile_name)
        instanceprofile_in_response = response.get("InstanceProfile")
        for values in instanceprofile_in_response["Roles"]:
            role_name = values["RoleName"]
            return role_name
        return ""
    except ClientError as e:
        raise RuntimeError(f"--- checkInstanceIAM --- [ERROR] Failed to get the role name from the instance profile: {str(e)}")


def get_attached_inline_policies(iam_client, role_name):
    try:
        response = iam_client.list_role_policies(RoleName=role_name)
        print(response)
        if len(response.get("PolicyNames", [])) == 0:
            return False
        else:
            return True
    except ClientError as e:
        raise RuntimeError(f"--- checkInstanceIAM --- [ERROR] Failed to list inline policies for {role_name}: {str(e)}")


def check_dhmc_status(ssm_client, dhmc_setting_id):
    try:
        response = ssm_client.get_service_setting(SettingId=dhmc_setting_id)
        return response["ServiceSetting"]["Status"]
    except ClientError as e:
        raise RuntimeError(f"--- checkInstanceIAM --- [ERROR] Failed to get the Default Host Management Configuration status: {str(e)}")


def checkInstanceIAM(ec2_client, ssm_client, iam_client, instance_id):

    instance_profile_name = get_instance_profile(ec2_client, instance_id)

    dhmc_setting_id = "/ssm/managed-instance/default-ec2-instance-management-role"
    print("Check Default Host Management Configuration:")
    dhmc_status = check_dhmc_status(ssm_client, dhmc_setting_id)
    print(f"--- checkInstanceIAM --- [INFO] Default Host Management Configuration is {dhmc_status}.")

    if not instance_profile_name:
        print(f"--- checkInstanceIAM --- [ERROR] No EC2 instance IAM profile attached to the instance: '{instance_id}'.")
        return

    role_name = get_iam_role_from_profile_name(iam_client, instance_profile_name)
    managed_policies = get_attached_managed_policies(iam_client, role_name)

    print(f"--- checkInstanceIAM --- Check for AWS managed policies attached to the instance profile '{instance_profile_name}':")
    required_policy_assigned = check_required_managed_policies(managed_policies)

    if required_policy_assigned:
        print(
            f"--- checkInstanceIAM --- [OK] Found an AWS managed policy attached to the instance profile '{instance_profile_name}' with required permissions."
        )
        return
    else:
        print(
            f"--- checkInstanceIAM --- [INFO] Not found an AWS managed policy attached to the instance profile '{instance_profile_name}' with required permissions."
        )

    print(f"--- checkInstanceIAM --- Check for inline policies attached to the instance profile '{instance_profile_name}':")
    inline_policies = get_attached_inline_policies(iam_client, role_name)

    if inline_policies:
        print(
            f"--- checkInstanceIAM --- [INFO] Found inline policies attached to the instance profile '{instance_profile_name}'. Make sure the policies grant the required minimum permissions."
        )
    else:
        print(f"--- checkInstanceIAM --- [ERROR] No permissions found attached to the EC2 instance profile '{instance_profile_name}'.")


def get_ping_status(ssm_client, instance_id):

    response = ssm_client.describe_instance_information()
    # print(response)
    resp = ssm_client.describe_instance_associations_status(InstanceId=instance_id)
    print(f"--- GetPingStatus --- Instance Associations Status => {resp.get("InstanceAssociationStatusInfos")}")
    for instance in response.get("InstanceInformationList"):
        if instance.get("InstanceId") == instance_id:
            print(f"--- GetPingStatus --- Instance Status => {instance.get("PingStatus")}")


def main():
    parser = argparse.ArgumentParser(description="Troubleshoot managed instance")

    parser.add_argument("--instance-id", required=True, help="The instance id")
    parser.add_argument("--region", required=False, default="us-east-1")

    args = parser.parse_args()

    ec2_client = boto3.client("ec2", region_name=args.region)
    ssm_client = boto3.client("ssm", region_name=args.region)
    iam_client = boto3.client("iam", region_name=args.region)

    print("*********************************************************")
    get_ping_status(ssm_client, args.instance_id)
    print("*********************************************************")

    property = InstanceProperties(ec2_client, args.instance_id)

    print(f"[INFO] ec2 instance information security_group_ids = {property.security_group_ids}")
    print(f"[INFO] ec2 instance information subnet_id = {property.subnet_id}")
    print(f"[INFO] ec2 instance information vpc_id = {property.vpc_id}")
    print(f"[INFO] ec2 instance information private_ip_address = {property.private_ip_address}")
    print(f"[INFO] ec2 instance information instance_profile = {property.instance_profile}")

    check_vpc_endpoint = checkVpcEndpoint(property, args.region)
    checkRouteTable(ec2_client, args.instance_id, property.subnet_id, property.vpc_id, check_vpc_endpoint.VpcEndpointId)
    checkNacl(ec2_client, args.instance_id, property.subnet_id, check_vpc_endpoint.VpcEndpointId, property.private_ip_address, check_vpc_endpoint.VpcEndpointSubnets)
    evaluator = SecurityGroupEvaluator(ec2_client, args.instance_id, check_vpc_endpoint.VpcEndpointId, property.security_group_ids, check_vpc_endpoint.VpcEndpointSecurityGroupIds, check_vpc_endpoint.VpcEndpointEnis)
    evaluator()
    
    checkInstanceIAM(ec2_client, ssm_client, iam_client, args.instance_id)


if __name__ == "__main__":
    main()