# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: LicenseRef-.amazon.com.-AmznSL-1.0
# Licensed under the Amazon Software License  http://aws.amazon.com/asl/

import argparse
# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: LicenseRef-.amazon.com.-AmznSL-1.0
# Licensed under the Amazon Software License  http://aws.amazon.com/asl/

from typing import Any, Dict, List, Tuple

import boto3
from botocore.exceptions import ClientError


def check_nacl_traffic_requirements(
    subnet_id: str, source: str, is_inbound: bool, required_traffic: Dict[str, List[List[int]]]
) -> list:
    network_acl_id, nacls = describe_network_acls(subnet_id)
    result = [f"Check network ACLs requirements on network ACL '{network_acl_id}':"]
    # Eval allowed inbound and outbound traffic from/to 0.0.0.0 and the instance private IP
    inbound, outbound = eval_acl_rules(nacls, [source])

    if is_inbound:
        # Check if the required inbound traffic.
        allowed_result = check_allowed(inbound, source, required_traffic, is_inbound)
        result.extend(allowed_result)
    else:
        allowed_result = check_allowed(outbound, source, required_traffic, is_inbound)
        result.extend(allowed_result)

    return result


def check_allowed(
    allowed_traffic: Dict[str, Dict[str, List[List[int]]]],
    source: str,
    required_traffic: Dict[str, List[List[int]]],
    is_inbound: bool,
) -> List[str]:
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
                                f"[OK] '{str_protocol}' inbound traffic allowed from '{source}' to '{required_range}'"
                            )
                        else:
                            print(
                                f"[OK] '{str_protocol}' outbound traffic allowed to '{source}' from '{required_range}'"
                            )
                        allowed = True
                        break
            if not allowed:
                if is_inbound:
                    print(
                        f"[ERROR] '{str_protocol}' inbound traffic not allowed from '{source}' to '{required_range}'"
                    )
                else:
                    print(
                        f"[ERROR] '{str_protocol}' outbound traffic not allowed to '{source}' from '{required_range}'"
                    )
            else:
                break
    return result


def eval_acl_rules(
    entries: List[Any], source: List[str]
) -> Tuple[Dict[str, Dict[str, List[List[int]]]], Dict[str, Dict[str, List[List[int]]]]]:
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
                protocol = get_std_protocol(rule["Protocol"])
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
                            in_allow[protocol] = range_add([from_port, to_port], in_allow.get(protocol, []))
                    else:
                        if network_in_source.subnet_of(network_in_acl):  # type: ignore
                            in_allow[protocol] = range_diff([from_port, to_port], in_allow.get(protocol, []))

                else:
                    if rule["RuleAction"] == "allow":
                        if network_in_source.subnet_of(network_in_acl):  # type: ignore
                            out_allow[protocol] = range_add([from_port, to_port], out_allow.get(protocol, []))
                    else:
                        if network_in_source.subnet_of(network_in_acl):  # type: ignore
                            out_allow[protocol] = range_diff([from_port, to_port], out_allow.get(protocol, []))

            allows_in[network_cidr] = dict(in_allow)
            allows_out[network_cidr] = dict(out_allow)

        return dict(allows_in), dict(allows_out)

    except Exception as e:
        raise ValueError("Failed to evaluate Network ACLs.", str(e))


def get_std_protocol(acl_protocol: str):
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


def range_add(new_port_range: List[int], interv: List[List[int]]) -> List[List[int]]:
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


def range_diff(new_range: List[int], interv: List[List[int]]) -> List[List[int]]:
    interv = range_add([], interv)
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


def describe_network_acls(subnet_id: str) -> Tuple[str, List[Any]]:
    """Analyse Network ACL rules for all traffic open from '0.0.0.0/0"""
    try:
        response = ec2_client.describe_network_acls(Filters=[{"Name": "association.subnet-id", "Values": [subnet_id]}])
        network_acls = response.get("NetworkAcls")[0].get("Entries", [])
        network_acl_id = response.get("NetworkAcls")[0].get("NetworkAclId")
        return network_acl_id, network_acls

    except ClientError as error:
        raise RuntimeError(
            f"[ERROR] Failed to describe the instance's Network ACLs from subnet {subnet_id}: {str(error)}."
        )


def main():
    parser = argparse.ArgumentParser(description="check vpc endpoint for SSM")

    parser.add_argument("--subnet-id", required=True)
    parser.add_argument("--instance-id", required=True)
    parser.add_argument("--vpc-endpoint-id", required=False)
    parser.add_argument("--region", required=False, default='us-east-1')
    parser.add_argument("--private-ip-address", required=True)
    parser.add_argument("--vpc-endpoint-subnets", required=False)
    

    args = parser.parse_args()

    ec2_client = boto3.client("ec2", region_name=args.region)

    instance_id = args.instance_id
    subnet_id = args.subnet_id
    vpc_endpoint_id = args.vpc_endpoint_id.split(",")
    instance_private_ip = args.private_ip_address
    vpc_endpoint_subnets = args.vpc_endpoint_subnets.split(",")


    if vpc_endpoint_id and subnet_id in vpc_endpoint_subnets:
        print(
            "[SKIPPED] VPC endpoint for Systems Manager is present and in the same subnet as the EC2 instance."
        )

    # Check requirements for instance's network ACL (ephemeral ports outbound)
    print(f"Check network ACLs requirements instance '{instance_id}' for instance subnet '{subnet_id}':")
    ephemeral_ports_outbound = {"-1": [[1024, 65535]]}
    instance_reqs = check_nacl_traffic_requirements(subnet_id, instance_private_ip, False, ephemeral_ports_outbound)
    print(f"Instance requirements: {instance_reqs}")

    if vpc_endpoint_id:
        for vpce_subnet_id in vpc_endpoint_subnets:
            # Check requirements for VPC endpoint's network ACL (ephemeral ports outbound)
            print(
                f"Check network ACLs requirements for the VPC endpoint '{vpc_endpoint_id}' subnet '{vpce_subnet_id}':"
            )
            ephemeral_ports_outbound = {"-1": [[1024, 65535]]}
            vpce_reqs = check_nacl_traffic_requirements(vpce_subnet_id, "0.0.0.0/0", False, ephemeral_ports_outbound)
            result.extend(vpce_reqs)
            https_inbound = {"tcp": [[443, 443]]}
            vpce_reqs = check_nacl_traffic_requirements(vpce_subnet_id, instance_private_ip, True, https_inbound)
            result.extend(vpce_reqs)

    return {"Message": "\n- ".join(result)}

if __name__ == "__main__":
    main()