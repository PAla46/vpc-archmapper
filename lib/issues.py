"""Misconfiguration detection for vpc-archmapper.

Analyzes the discovered resources and returns a list of issues, each with a
severity, a human-readable description, and a remediation suggestion.
"""


class Issue:
    SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}

    def __init__(self, severity, resource, title, description, remediation):
        self.severity = severity
        self.resource = resource
        self.title = title
        self.description = description
        self.remediation = remediation

    def as_dict(self):
        return {
            "severity": self.severity,
            "resource": self.resource,
            "title": self.title,
            "description": self.description,
            "remediation": self.remediation,
        }


class IssueDetector:
    def __init__(self, data, analysis):
        self.data = data
        self.analysis = analysis
        self.issues = []

    def add(self, severity, resource, title, description, remediation):
        self.issues.append(
            Issue(severity, resource, title, description, remediation)
        )

    def run(self):
        self.check_open_security_groups()
        self.check_broad_port_ranges()
        self.check_all_protocol_rules()
        self.check_public_subnet_routing()
        self.check_blackhole_routes()
        self.check_unused_security_groups()
        self.check_permissive_nacls()
        self.check_open_ssh_rdp()
        self.check_broad_egress()
        self.check_default_vpc()
        self.check_nat_public_placement()
        self.check_vpc_peering_stale()
        self.issues.sort(key=lambda i: Issue.SEVERITY_ORDER.get(i.severity, 9))
        return self.issues

    # ------------------------------------------------------------------
    def _source_sg_owners(self, sg_id):
        return self.analysis._resource_sg_map.get(sg_id, [])

    def _is_default_sg(self, sg):
        """Return True if this is an AWS-managed default security group.

        Every newly created VPC gets a 'default' security group. In the *default*
        VPC this group is automatically configured to allow all self-inbound and
        all outbound traffic. These rules are by-design and are not meaningful
        findings, so they are excluded from misconfiguration checks.
        """
        if sg.get("name") != "default":
            return False
        vpc = self.data["vpcs"].get(sg.get("vpc_id", ""), {})
        return bool(vpc.get("is_default"))

    def _manageable_sgs(self):
        """Yield security groups that are not AWS-managed default groups."""
        for sg in self.data["security_groups"].values():
            if self._is_default_sg(sg):
                continue
            yield sg

    def check_open_security_groups(self):
        """Flag any SG allowing ingress from 0.0.0.0/0 or ::/0."""
        for sg in self._manageable_sgs():
            for rule in sg["ingress"]:
                for target in rule["targets"]:
                    if target["type"] == "cidr" and target["value"] in (
                        "0.0.0.0/0",
                        "::/0",
                    ):
                        owners = self._source_sg_owners(sg["id"])
                        owner_desc = " (attached to: " + ", ".join(owners) + ")" if owners else ""
                        self.add(
                            "high",
                            sg["name"] or sg["id"],
                            "Internet-exposed security group",
                            f"{sg['name'] or sg['id']} allows traffic from "
                            f"{target['value']} (all IPs) on "
                            f"{self.analysis.port_label(rule)}.{owner_desc}",
                            "Restrict ingress to specific CIDRs or security groups "
                            "instead of 0.0.0.0/0 unless the resource is intended "
                            "to be public (e.g. a web-facing ALB).",
                        )

    def check_all_protocol_rules(self):
        """Flag SG rules allowing ALL protocols.

        ALL-protocols *ingress* is a genuine high-risk finding (any host can
        reach any port). ALL-protocols *egress* is common and lower risk; it is
        reported separately by check_broad_egress, so we only flag ingress here.
        """
        for sg in self._manageable_sgs():
            for rule in sg["ingress"]:
                if rule["protocol"] == "ALL":
                    for target in rule["targets"]:
                        if target["type"] == "cidr" and target["value"] in (
                            "0.0.0.0/0",
                            "::/0",
                        ):
                            owners = self._source_sg_owners(sg["id"])
                            owner_desc = (
                                " (attached to: " + ", ".join(owners) + ")"
                                if owners
                                else ""
                            )
                            self.add(
                                "high",
                                sg["name"] or sg["id"],
                                "All-protocols ingress from internet",
                                f"{sg['name'] or sg['id']} allows ALL protocols "
                                f"from {target['value']} (ingress).{owner_desc}",
                                "Define granular protocol/port ingress rules. "
                                "Only allow ip protocols needed by the workload.",
                            )

    def check_broad_port_ranges(self):
        """Flag extremely broad port ranges (e.g. 1-65535) on non-open SGs."""
        for sg in self._manageable_sgs():
            for rule in sg["ingress"]:
                frm = rule.get("from_port")
                to = rule.get("to_port")
                if frm is None or to is None:
                    continue
                if frm == 0 and to >= 65535:
                    self.add(
                        "medium",
                        sg["name"] or sg["id"],
                        "Broad port range",
                        f"{sg['name'] or sg['id']} allows all ports "
                        f"({rule['protocol']}) from {self._targets_desc(rule['targets'])}.",
                        "Narrow the port range to the specific ports the "
                        "application listens on.",
                    )

    def _targets_desc(self, targets):
        return ", ".join(
            t["value"] if t["type"] in ("cidr", "sg", "prefix-list") else str(t["value"])
            for t in targets
        ) or "unknown"

    def check_open_ssh_rdp(self):
        """Flag SSH (22) or RDP (3389) open to the internet."""
        for sg in self._manageable_sgs():
            for rule in sg["ingress"]:
                frm = rule.get("from_port")
                to = rule.get("to_port")
                is_ssh = (frm is not None and frm <= 22 <= (to or frm))
                is_rdp = (frm is not None and frm <= 3389 <= (to or frm))
                if not (is_ssh or is_rdp):
                    continue
                for target in rule["targets"]:
                    if target["type"] == "cidr" and target["value"] in ("0.0.0.0/0", "::/0"):
                        self.add(
                            "high",
                            sg["name"] or sg["id"],
                            f"Open {'SSH' if is_ssh else 'RDP'} to internet",
                            f"{sg['name'] or sg['id']} exposes "
                            f"{'SSH (22)' if is_ssh else 'RDP (3389)'} to all IPs.",
                            "Allow SSH/RDP only from trusted admin CIDRs or "
                            "use SSM Session Manager / a bastion host.",
                        )

    def check_public_subnet_routing(self):
        """Flag subnets that are public but lack a route to an IGW, and
        subnets that are private but have an IGW route (i.e. mis-classified)."""
        rt_by_subnet = {}
        for rt in self.data["route_tables"].values():
            for assoc in rt["associations"]:
                if assoc["subnet_id"]:
                    rt_by_subnet[assoc["subnet_id"]] = rt

        for subnet in self.data["subnets"].values():
            rt = rt_by_subnet.get(subnet["id"])
            if not rt:
                continue
            has_igw = any(
                r["target_type"] == "gateway"
                and r["target"].startswith("igw-")
                and not r["is_local"]
                for r in rt["routes"]
            )
            is_default_vpc_subnet = False
            vpc = self.data["vpcs"].get(subnet["vpc_id"], {})
            if vpc.get("is_default") and subnet["vpc_id"]:
                # default VPC subnets auto-route to IGW; skip warning
                is_default_vpc_subnet = True

            # Public subnet missing an IGW route
            if has_igw and self._looks_public(subnet):
                pass  # correctly public
            elif self._looks_private(subnet) and has_igw and not vpc.get("is_default"):
                self.add(
                    "low",
                    subnet.get("name") or subnet["id"],
                    "Private subnet routes to internet",
                    f"Subnet {subnet.get('name') or subnet['id']} has a direct "
                    f"Internet Gateway route but no NAT gateway — instances may "
                    f"have unintended direct internet access.",
                    "Ensure private subnets route to the internet only through a "
                    "NAT gateway, not directly to an IGW.",
                )

    def _looks_public(self, subnet):
        # A subnet is "public" by convention if it has an IGW route; we use
        # the classification computed in the analyzer.
        return self.analysis._subnet_classification.get(subnet["id"], False)

    def _looks_private(self, subnet):
        return not self._looks_public(subnet)

    def check_blackhole_routes(self):
        """Flag routes in 'blackhole' state."""
        for rt in self.data["route_tables"].values():
            for route in rt["routes"]:
                if route["state"] == "blackhole":
                    self.add(
                        "medium",
                        rt["id"],
                        "Blackhole route",
                        f"Route table {rt['id']} has a blackhole route for "
                        f"{route['cidr']} via {route['target'] or 'deleted target'}.",
                        "The route target is unavailable/deleted. Restore the "
                        "target or remove the stale route.",
                    )

    def check_unused_security_groups(self):
        """Flag security groups not attached to any discovered resource.

        AWS-managed default SGs are excluded (every VPC has one whether or not
        it is in use, so flagging them is pure noise).
        """
        resource_sg_map = self.analysis._resource_sg_map
        for sg in self._manageable_sgs():
            sg_id = sg["id"]
            if sg_id not in resource_sg_map:
                self.add(
                    "low",
                    sg.get("name") or sg_id,
                    "Unused security group",
                    f"Security group {sg.get('name') or sg_id} is not attached "
                    "to any discovered resource (EC2, RDS, ElastiCache).",
                    "Review and remove unused security groups to reduce "
                    "maintenance overhead and attack surface.",
                )

    def check_permissive_nacls(self):
        """Flag NACLs allowing ALL traffic in either direction."""
        for nacl in self.data["network_acls"].values():
            if nacl["is_default"]:
                continue
            for entry in nacl["entries"]:
                # Protocol -1 means all
                if str(entry["protocol"]) in ("-1", "all") and entry["cidr"] in (
                    "0.0.0.0/0",
                    "::/0",
                ):
                    if entry["from_port"] is None and entry["to_port"] is None:
                        self.add(
                            "medium",
                            nacl["id"],
                            "Permissive network ACL",
                            f"NACL {nacl['id']} allows all {entry['direction']} "
                            f"traffic from {entry['cidr']}.",
                            "Use NACLs only for explicit deny rules or when "
                            "stateless filtering is required; otherwise rely on "
                            "security groups.",
                        )

    def check_broad_egress(self):
        """Flag SG egress rules open to all CIDRs (common but worth noting).

        AWS-managed default SGs always allow ALL outbound and are excluded here;
        only custom security groups are reported.
        """
        for sg in self._manageable_sgs():
            for rule in sg["egress"]:
                for target in rule["targets"]:
                    if target["type"] == "cidr" and target["value"] in ("0.0.0.0/0", "::/0"):
                        self.add(
                            "info",
                            sg.get("name") or sg["id"],
                            "Broad egress rule",
                            f"{sg.get('name') or sg['id']} allows all egress to "
                            f"{target['value']} on {self.analysis.port_label(rule)}.",
                            "If the workload does not need full outbound access, "
                            "restrict egress to required destinations/ports.",
                        )

    def check_default_vpc(self):
        """Warn about resources running in the default VPC."""
        default_vpcs = {
            v["id"]: v for v in self.data["vpcs"].values() if v.get("is_default")
        }
        for inst in self.data["instances"].values():
            if inst["vpc_id"] in default_vpcs and inst.get("name"):
                self.add(
                    "medium",
                    inst.get("name") or inst["id"],
                    "Resource in default VPC",
                    f"EC2 instance {inst.get('name') or inst['id']} runs in the "
                    "AWS default VPC, which allows all internal traffic by default.",
                    "Consider migrating workloads to a purpose-built VPC with "
                    "defined public/private segmentation.",
                )

    def check_nat_public_placement(self):
        """Flag NAT gateways not placed in a public subnet."""
        public_subnets = {
            sid for sid, is_pub in self.analysis._subnet_classification.items() if is_pub
        }
        for ngw in self.data["nat_gateways"].values():
            if ngw["subnet_id"] not in public_subnets:
                self.add(
                    "medium",
                    ngw["id"],
                    "NAT gateway not in public subnet",
                    f"NAT gateway {ngw['id']} is not in a public subnet "
                    f"({ngw.get('subnet_id') or 'unknown'}).",
                    "Place NAT gateways in public subnets so they can route to "
                    "the internet gateway.",
                )

    def check_vpc_peering_stale(self):
        """Flag peering connections that are still pending or rejected."""
        for peering in self.data["peering_connections"].values():
            if peering["status"] in ("pending-acceptance", "rejected", "provisioning"):
                self.add(
                    "low",
                    peering["id"],
                    f"Peering connection {peering['status']}",
                    f"VPC peering {peering['id']} between "
                    f"{peering['requester_vpc']} and {peering['accepter_vpc']} "
                    f"is in state '{peering['status']}'.",
                    "Accept or delete the pending/rejected peering connection.",
                )
