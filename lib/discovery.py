"""AWS resource discovery for vpc-archmapper.

Enumerates all read-only networking resources across one or more regions.
Pure Describe/List calls only; requires read-only IAM access.
"""

import boto3
from botocore.exceptions import ClientError


class DiscoveryError(Exception):
    """Raised when an AWS discovery call fails in a non-recoverable way."""


def _safe_call(func, *args, region=None, **kwargs):
    """Run an AWS API call, catching and logging permission errors.

    Returns (result, None) on success, or (None, error_message) on failure so
    the caller can degrade gracefully instead of crashing.
    """
    try:
        if region:
            func = _region_bound(func, region)
        return func(*args, **kwargs), None
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "Unknown")
        if code in ("AccessDenied", "UnauthorizedOperation", "OptInRequired"):
            return None, f"Access denied ({code})"
        return None, str(exc)
    except Exception as exc:  # pragma: no cover - defensive
        return None, str(exc)


def _region_bound(func, region):
    """Return a client-bound variant that always targets `region`."""
    def wrapped(*args, **kwargs):
        return func(*args, RegionName=region, **kwargs)
    return wrapped


class AWSDiscovery:
    """Discovers networking resources and returns a normalized data model."""

    def __init__(self, session=None, regions=None):
        self.session = session or boto3.Session()
        self.data = {
            "regions": [],
            "vpcs": {},
            "subnets": {},
            "route_tables": {},
            "security_groups": {},
            "network_acls": {},
            "instances": {},
            "nat_gateways": {},
            "internet_gateways": {},
            "vpc_endpoints": {},
            "peering_connections": {},
            "transit_gateways": {},
            "load_balancers": {},
            "rds_instances": {},
            "elasticache_clusters": {},
            "errors": [],
        }
        self.regions = regions or self._discover_regions()

    def _discover_regions(self):
        ec2 = self.session.client("ec2", region_name="us-east-1")
        try:
            resp = ec2.describe_regions()
            return [r["RegionName"] for r in resp["Regions"]]
        except Exception as exc:
            self.data["errors"].append(
                f"Could not list regions: {exc} — falling back to us-east-1."
            )
            return ["us-east-1"]

    def record_error(self, region, what, message):
        self.data["errors"].append(f"[{region}] {what}: {message}")

    def _vpc_summary(self, vpc, region):
        name = ""
        tags = vpc.get("Tags", [])
        for t in tags:
            if t["Key"] == "Name":
                name = t["Value"]
        return {
            "id": vpc["VpcId"],
            "cidr": vpc.get("CidrBlock"),
            "name": name,
            "region": region,
            "is_default": vpc.get("IsDefault", False),
            "tags": tags,
        }

    def discover_vpcs(self, region):
        client = self.session.client("ec2", region_name=region)
        resp, err = _safe_call(client.describe_vpcs)
        if err:
            self.record_error(region, "describe-vpcs", err)
            return
        for vpc in resp["Vpcs"]:
            summary = self._vpc_summary(vpc, region)
            self.data["vpcs"][vpc["VpcId"]] = summary

    def discover_subnets(self, region):
        client = self.session.client("ec2", region_name=region)
        resp, err = _safe_call(client.describe_subnets)
        if err:
            self.record_error(region, "describe-subnets", err)
            return
        for subnet in resp["Subnets"]:
            vpc_id = subnet["VpcId"]
            name = next(
                (t["Value"] for t in subnet.get("Tags", []) if t["Key"] == "Name"),
                "",
            )
            self.data["subnets"][subnet["SubnetId"]] = {
                "id": subnet["SubnetId"],
                "vpc_id": vpc_id,
                "cidr": subnet.get("CidrBlock"),
                "az": subnet.get("AvailabilityZone", ""),
                "name": name,
                "region": region,
            }

    def discover_route_tables(self, region):
        client = self.session.client("ec2", region_name=region)
        resp, err = _safe_call(client.describe_route_tables)
        if err:
            self.record_error(region, "describe-route-tables", err)
            return
        for rt in resp["RouteTables"]:
            vpc_id = rt["VpcId"]
            routes = []
            for route in rt.get("Routes", []):
                target = (
                    route.get("GatewayId")
                    or route.get("NatGatewayId")
                    or route.get("TransitGatewayId")
                    or route.get("VpcPeeringConnectionId")
                    or route.get("NetworkInterfaceId")
                    or route.get("EgressOnlyInternetGatewayId")
                    or route.get("LocalGatewayId")
                    or route.get("CarrierGatewayId")
                    or ""
                )
                routes.append({
                    "cidr": route.get("DestinationCidrBlock")
                    or route.get("DestinationIpv6CidrBlock")
                    or route.get("DestinationPrefixListId")
                    or "",
                    "target": target,
                    "state": route.get("State"),
                    "target_type": _target_type(route),
                    "is_local": route.get("Origin") == "CreateRouteTable",
                })
            associations = []
            for assoc in rt.get("Associations", []):
                associations.append({
                    "id": assoc.get("RouteTableAssociationId"),
                    "subnet_id": assoc.get("SubnetId"),
                    "main": assoc.get("Main", False),
                })
            self.data["route_tables"][rt["RouteTableId"]] = {
                "id": rt["RouteTableId"],
                "vpc_id": vpc_id,
                "routes": routes,
                "associations": associations,
                "region": region,
            }

    def discover_security_groups(self, region):
        client = self.session.client("ec2", region_name=region)
        resp, err = _safe_call(client.describe_security_groups)
        if err:
            self.record_error(region, "describe-security-groups", err)
            return
        for sg in resp["SecurityGroups"]:
            vpc_id = sg.get("VpcId", "")
            ingress = [
                self._normalize_rule(r)
                for r in sg.get("IpPermissions", [])
            ]
            egress = [
                self._normalize_rule(r)
                for r in sg.get("IpPermissionsEgress", [])
            ]
            self.data["security_groups"][sg["GroupId"]] = {
                "id": sg["GroupId"],
                "name": sg.get("GroupName"),
                "description": sg.get("Description", ""),
                "vpc_id": vpc_id,
                "ingress": ingress,
                "egress": egress,
                "region": region,
            }

    def _normalize_rule(self, rule):
        """Convert a single IPPermission into a simplified rule dict."""
        from_port = rule.get("FromPort")
        to_port = rule.get("ToPort")
        protocol = rule.get("IpProtocol", "-1")
        if protocol == "-1":
            protocol = "ALL"

        targets = []
        for ip in rule.get("IpRanges", []):
            targets.append({"type": "cidr", "value": ip.get("CidrIp", "")})
        for ipv6 in rule.get("Ipv6Ranges", []):
            targets.append({"type": "cidr", "value": ipv6.get("CidrIpv6", "")})
        for pre in rule.get("PrefixListIds", []):
            targets.append({"type": "prefix-list", "value": pre.get("PrefixListId", "")})
        for ref in rule.get("UserIdGroupPairs", []):
            targets.append({
                "type": "sg",
                "value": ref.get("GroupId", ""),
                "vpc": ref.get("VpcId", ""),
            })
        for ref in rule.get("ReferencedGroupInfo", []):
            targets.append({
                "type": "sg",
                "value": ref.get("GroupId", ""),
                "vpc": ref.get("VpcId", ""),
            })

        return {
            "protocol": protocol,
            "from_port": from_port,
            "to_port": to_port,
            "targets": targets,
        }

    def discover_network_acls(self, region):
        client = self.session.client("ec2", region_name=region)
        resp, err = _safe_call(client.describe_network_acls)
        if err:
            self.record_error(region, "describe-network-acls", err)
            return
        for nacl in resp["NetworkAcls"]:
            vpc_id = nacl["VpcId"]
            entries = []
            for entry in sorted(
                nacl.get("Entries", []), key=lambda e: e.get("RuleNumber", 0)
            ):
                entries.append({
                    "number": entry.get("RuleNumber"),
                    "action": entry.get("RuleAction"),
                    "direction": entry.get("Egress", False) and "egress" or "ingress",
                    "protocol": entry.get("Protocol"),
                    "cidr": entry.get("CidrBlock")
                    or entry.get("Ipv6CidrBlock")
                    or "",
                    "from_port": entry.get("PortRange", {}).get("From"),
                    "to_port": entry.get("PortRange", {}).get("To"),
                })
            self.data["network_acls"][nacl["NetworkAclId"]] = {
                "id": nacl["NetworkAclId"],
                "vpc_id": vpc_id,
                "is_default": nacl.get("IsDefault", False),
                "entries": entries,
                "region": region,
            }

    def discover_instances(self, region):
        client = self.session.client("ec2", region_name=region)
        resp, err = _safe_call(client.describe_instances)
        if err:
            self.record_error(region, "describe-instances", err)
            return
        for reservation in resp.get("Reservations", []):
            for inst in reservation.get("Instances", []):
                if inst.get("State", {}).get("Name") == "terminated":
                    continue
                vpc_id = inst.get("VpcId", "")
                if not vpc_id:
                    continue
                name = next(
                    (t["Value"] for t in inst.get("Tags", []) if t["Key"] == "Name"),
                    "",
                )
                self.data["instances"][inst["InstanceId"]] = {
                    "id": inst["InstanceId"],
                    "name": name,
                    "vpc_id": vpc_id,
                    "subnet_id": inst.get("SubnetId", ""),
                    "security_groups": [
                        sg["GroupId"]
                        for sg in inst.get("SecurityGroups", [])
                    ],
                    "private_ip": inst.get("PrivateIpAddress", ""),
                    "type": inst.get("InstanceType", ""),
                    "state": inst.get("State", {}).get("Name", ""),
                    "region": region,
                }

    def discover_nat_gateways(self, region):
        client = self.session.client("ec2", region_name=region)
        resp, err = _safe_call(client.describe_nat_gateways)
        if err:
            self.record_error(region, "describe-nat-gateways", err)
            return
        for ngw in resp.get("NatGateways", []):
            if ngw.get("State") == "deleted":
                continue
            self.data["nat_gateways"][ngw["NatGatewayId"]] = {
                "id": ngw["NatGatewayId"],
                "vpc_id": ngw.get("VpcId", ""),
                "subnet_id": ngw.get("SubnetId", ""),
                "state": ngw.get("State", ""),
                "region": region,
            }

    def discover_internet_gateways(self, region):
        client = self.session.client("ec2", region_name=region)
        resp, err = _safe_call(client.describe_internet_gateways)
        if err:
            self.record_error(region, "describe-internet-gateways", err)
            return
        for igw in resp.get("InternetGateways", []):
            for att in igw.get("Attachments", []):
                vpc_id = att.get("VpcId")
                if vpc_id and att.get("State") == "available":
                    self.data["internet_gateways"][igw["InternetGatewayId"]] = {
                        "id": igw["InternetGatewayId"],
                        "vpc_id": vpc_id,
                        "region": region,
                    }

    def discover_vpc_endpoints(self, region):
        client = self.session.client("ec2", region_name=region)
        paginator = client.get_paginator("describe_vpc_endpoints")
        try:
            for page in paginator.paginate():
                for ep in page.get("VpcEndpoints", []):
                    self.data["vpc_endpoints"][ep["VpcEndpointId"]] = {
                        "id": ep["VpcEndpointId"],
                        "vpc_id": ep.get("VpcId", ""),
                        "service": ep.get("ServiceName", ""),
                        "type": ep.get("VpcEndpointType", ""),
                        "region": region,
                    }
        except ClientError as exc:
            self.record_error(region, "describe-vpc-endpoints", str(exc))

    def discover_peering_connections(self, region):
        client = self.session.client("ec2", region_name=region)
        resp, err = _safe_call(client.describe_vpc_peering_connections)
        if err:
            self.record_error(region, "describe-vpc-peering", err)
            return
        for peering in resp.get("VpcPeeringConnections", []):
            if peering.get("Status", {}).get("Code") in ("deleted", "expired", "failed"):
                continue
            self.data["peering_connections"][peering["VpcPeeringConnectionId"]] = {
                "id": peering["VpcPeeringConnectionId"],
                "requester_vpc": peering.get("RequesterVpcInfo", {}).get("VpcId", ""),
                "accepter_vpc": peering.get("AccepterVpcInfo", {}).get("VpcId", ""),
                "status": peering.get("Status", {}).get("Code", ""),
                "region": region,
            }

    def discover_transit_gateways(self, region):
        client = self.session.client("ec2", region_name=region)
        resp, err = _safe_call(client.describe_transit_gateways)
        if err:
            self.record_error(region, "describe-transit-gateways", err)
            return
        tgw_ids = []
        for tgw in resp.get("TransitGateways", []):
            if tgw.get("State") == "deleted":
                continue
            self.data["transit_gateways"][tgw["TransitGatewayId"]] = {
                "id": tgw["TransitGatewayId"],
                "region": region,
                "attachments": {},
            }
            tgw_ids.append(tgw["TransitGatewayId"])

        # Discovery of attachments (best-effort, per tgw)
        for tgw_id in tgw_ids:
            self._discover_tgw_attachments(client, tgw_id, region)

    def _discover_tgw_attachments(self, client, tgw_id, region):
        try:
            att_resp = client.describe_transit_gateway_attachments(
                Filters=[{
                    "Name": "transit-gateway-id",
                    "Values": [tgw_id],
                }]
            )
            for att in att_resp.get("TransitGatewayAttachments", []):
                if att.get("State") == "deleted":
                    continue
                resource = att.get("ResourceId", "")
                rtype = att.get("ResourceType", "")
                self.data["transit_gateways"][tgw_id]["attachments"][
                    att["TransitGatewayAttachmentId"]
                ] = {
                    "id": att["TransitGatewayAttachmentId"],
                    "resource_id": resource,
                    "resource_type": rtype,
                    "vpc_id": self._attachment_to_vpc(att, resource, rtype),
                }
        except ClientError:
            # Attachment-level permission errors are tolerated
            pass

    def _attachment_to_vpc(self, att, resource, rtype):
        if rtype == "vpc":
            return resource
        return None

    def discover_load_balancers(self, region):
        try:
            client = self.session.client("elbv2", region_name=region)
            paginator = client.get_paginator("describe_load_balancers")
            for page in paginator.paginate():
                for lb in page.get("LoadBalancers", []):
                    if lb.get("State", {}).get("Code") == "active":
                        self.data["load_balancers"][lb["LoadBalancerArn"]] = {
                            "id": lb["LoadBalancerArn"].rsplit("/", 1)[-1],
                            "name": lb.get("LoadBalancerName", ""),
                            "type": lb.get("Type", ""),
                            "vpc_id": lb.get("VpcId", ""),
                            "scheme": lb.get("Scheme", ""),
                            "region": region,
                        }
        except ClientError as exc:
            self.record_error(region, "describe-load-balancers", str(exc))

    def discover_rds_instances(self, region):
        try:
            client = self.session.client("rds", region_name=region)
            paginator = client.get_paginator("describe_db_instances")
            for page in paginator.paginate():
                for db in page.get("DBInstances", []):
                    if db.get("DBInstanceStatus") == "deleted":
                        continue
                    self.data["rds_instances"][db["DBInstanceIdentifier"]] = {
                        "id": db["DBInstanceIdentifier"],
                        "vpc_id": db.get("DBSubnetGroup", {}).get("VpcId", ""),
                        "sg_ids": [
                            sg["VpcSecurityGroupId"]
                            for sg in db.get("VpcSecurityGroups", [])
                            if sg.get("Status") == "active"
                        ],
                        "engine": db.get("Engine", ""),
                        "region": region,
                    }
        except ClientError as exc:
            self.record_error(region, "describe-db-instances", str(exc))

    def discover_elasticache_clusters(self, region):
        try:
            client = self.session.client("elasticache", region_name=region)
            paginator = client.get_paginator("describe_cache_clusters")
            for page in paginator.paginate():
                for cluster in page.get("CacheClusters", []):
                    self.data["elasticache_clusters"][cluster["CacheClusterId"]] = {
                        "id": cluster["CacheClusterId"],
                        "sg_ids": [
                            sg["SecurityGroupId"]
                            for sg in cluster.get("SecurityGroups", [])
                        ],
                        "engine": cluster.get("Engine", ""),
                        "region": region,
                    }
        except ClientError as exc:
            self.record_error(region, "describe-cache-clusters", str(exc))

    def discover_region(self, region):
        """Run all discovery methods for a single region."""
        self.data["regions"].append(region)
        self.discover_vpcs(region)
        self.discover_subnets(region)
        self.discover_route_tables(region)
        self.discover_security_groups(region)
        self.discover_network_acls(region)
        self.discover_instances(region)
        self.discover_nat_gateways(region)
        self.discover_internet_gateways(region)
        self.discover_vpc_endpoints(region)
        self.discover_peering_connections(region)
        self.discover_transit_gateways(region)
        self.discover_load_balancers(region)
        self.discover_rds_instances(region)
        self.discover_elasticache_clusters(region)

    def run(self):
        for region in self.regions:
            self.discover_region(region)
        return self.data


def _target_type(route):
    """Determine the type of the route target from route keys."""
    for key, type_name in (
        ("GatewayId", "gateway"),
        ("NatGatewayId", "nat"),
        ("TransitGatewayId", "tgw"),
        ("VpcPeeringConnectionId", "peering"),
        ("NetworkInterfaceId", "eni"),
        ("EgressOnlyInternetGatewayId", "egress-igw"),
        ("LocalGatewayId", "local-gateway"),
        ("CarrierGatewayId", "carrier-gateway"),
    ):
        if route.get(key):
            return type_name
    return "unknown"
