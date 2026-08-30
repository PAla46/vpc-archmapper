"""Connectivity and routing analysis for vpc-archmapper.

Builds an abstract graph of which resources can communicate with each other,
based on security group rules, routing tables, and cross-VPC connections.
"""


class NetworkAnalyzer:
    def __init__(self, data):
        self.data = data
        self._subnet_classification = {}
        self._resource_nodes = {}
        self._edges = []
        self._resource_sg_map = {}

    # ------------------------------------------------------------------
    # Subnet classification
    # ------------------------------------------------------------------
    def classify_subnets(self):
        """Classify each subnet as public/private based on an IGW route."""
        classification = {}

        # Map subnet_id -> route table (handle main table for unassociated)
        vpc_main_tables = {}
        for rt in self.data["route_tables"].values():
            for assoc in rt["associations"]:
                if assoc["main"]:
                    vpc_main_tables.setdefault(rt["vpc_id"], rt["id"])
                if assoc["subnet_id"]:
                    classification[assoc["subnet_id"]] = rt["id"]
            if rt["vpc_id"] not in vpc_main_tables and not rt["associations"]:
                vpc_main_tables.setdefault(rt["vpc_id"], rt["id"])

        route_to_igw = {}
        for rt in self.data["route_tables"].values():
            route_to_igw[rt["id"]] = any(
                r["target_type"] == "gateway"
                and r["target"].startswith("igw-")
                and not r["is_local"]
                for r in rt["routes"]
            )

        result = {}
        for subnet in self.data["subnets"].values():
            rt_id = classification.get(subnet["id"])
            if not rt_id:
                rt_id = vpc_main_tables.get(subnet["vpc_id"], "")
            is_public = self._subnet_is_public(rt_id, route_to_igw)
            result[subnet["id"]] = is_public

        self._subnet_classification = result
        return result

    def _subnet_is_public(self, rt_id, route_to_igw):
        if not rt_id:
            return False
        return route_to_igw.get(rt_id, False)

    # ------------------------------------------------------------------
    # Resource node building
    # ------------------------------------------------------------------
    def build_resource_nodes(self):
        """Create a stable set of 'nodes' representing concrete resources.

        Each node groups an EC2 instance (or other compute resource) together
        with its security groups so we can trace connectivity through them.
        """
        nodes = {}
        sg_owners = {}

        # EC2 instances
        for inst in self.data["instances"].values():
            nid = "ec2:" + inst["id"]
            nodes[nid] = {
                "id": inst["id"],
                "label": inst["name"] or inst["id"],
                "type": "ec2",
                "vpc_id": inst["vpc_id"],
                "subnet_id": inst["subnet_id"],
                "sg_ids": inst["security_groups"],
                "region": inst["region"],
            }
            for sg_id in inst["security_groups"]:
                sg_owners.setdefault(sg_id, []).append(nid)

        # Load balancers
        for lb in self.data["load_balancers"].values():
            nid = "elb:" + lb["name"]
            nodes[nid] = {
                "id": lb["name"],
                "label": lb["name"],
                "type": "elb",
                "vpc_id": lb["vpc_id"],
                "subnet_id": "",
                "sg_ids": [],
                "region": lb["region"],
                "extra": f"{lb['type']} · {lb['scheme']}",
            }

        # RDS instances
        for db in self.data["rds_instances"].values():
            nid = "rds:" + db["id"]
            nodes[nid] = {
                "id": db["id"],
                "label": db["id"],
                "type": "rds",
                "vpc_id": db["vpc_id"],
                "subnet_id": "",
                "sg_ids": db["sg_ids"],
                "region": db["region"],
                "extra": db["engine"],
            }
            for sg_id in db["sg_ids"]:
                sg_owners.setdefault(sg_id, []).append(nid)

        # ElastiCache clusters
        for cluster in self.data["elasticache_clusters"].values():
            nid = "cache:" + cluster["id"]
            nodes[nid] = {
                "id": cluster["id"],
                "label": cluster["id"],
                "type": "cache",
                "vpc_id": "",
                "subnet_id": "",
                "sg_ids": cluster["sg_ids"],
                "region": cluster["region"],
                "extra": cluster["engine"],
            }
            for sg_id in cluster["sg_ids"]:
                sg_owners.setdefault(sg_id, []).append(nid)

        # NAT gateways
        for ngw in self.data["nat_gateways"].values():
            nid = "nat:" + ngw["id"]
            nodes[nid] = {
                "id": ngw["id"],
                "label": ngw["id"],
                "type": "nat",
                "vpc_id": ngw["vpc_id"],
                "subnet_id": ngw["subnet_id"],
                "sg_ids": [],
                "region": ngw["region"],
            }

        # VPC endpoints
        for ep in self.data["vpc_endpoints"].values():
            nid = "endpoint:" + ep["id"]
            nodes[nid] = {
                "id": ep["id"],
                "label": ep["service"].split(".")[-1] or ep["id"],
                "type": "vpc-endpoint",
                "vpc_id": ep["vpc_id"],
                "subnet_id": "",
                "sg_ids": [],
                "region": ep["region"],
                "extra": ep["service"],
            }

        self._resource_nodes = nodes
        self._resource_sg_map = sg_owners

        # Add subnet association to nodes that have a subnet
        for nid, node in nodes.items():
            subnet_id = node["subnet_id"]
            if subnet_id:
                subnet = self.data["subnets"].get(subnet_id, {})
                node["subnet_label"] = subnet.get("name") or subnet.get("id")
                node["az"] = subnet.get("az", "")
                node["is_public"] = self._subnet_classification.get(subnet_id, False)
            else:
                node["subnet_label"] = ""
                node["az"] = ""
                node["is_public"] = False

        return nodes

    # ------------------------------------------------------------------
    # Security group connectivity
    # ------------------------------------------------------------------
    def build_sg_connectivity(self):
        """Return dict sg_id -> list of {target_sg, ports, protocol} flows.

        Only includes SG to SG references (CIDR flows are treated as external
        and flagged separately).
        """
        sg_to_sg = {}
        for sg_id, sg in self.data["security_groups"].items():
            flows = []
            for rule in sg["ingress"]:
                for target in rule["targets"]:
                    if target["type"] == "sg":
                        flows.append({
                            "source_sg": target["value"],
                            "protocol": rule["protocol"],
                            "from_port": rule["from_port"],
                            "to_port": rule["to_port"],
                            "rule": rule,
                        })
            if flows:
                sg_to_sg[sg_id] = flows
        return sg_to_sg

    def port_label(self, rule):
        """Human-readable port/proto label for an edge."""
        proto = rule.get("protocol", "ALL")
        frm = rule.get("from_port")
        to = rule.get("to_port")
        if proto == "ALL":
            return "ALL"
        if frm is None:
            return f"{proto}"
        if frm == to:
            return f"{proto} {frm}"
        return f"{proto} {frm}-{to}"

    def build_edges(self):
        """Build final edge list connecting resources via SG rules.

        An edge exists between resource A and resource B when B's security
        group allows ingress from A's security group (or the SG that A is in).
        Cross-VPC connections (peering / TGW) also produce edges.
        """
        edges = []
        seen = set()

        sg_flows = self.build_sg_connectivity()

        # Map VPC -> resources so we can resolve SG owners across VPCs too
        # when peering is involved.

        def resolve_flow_to_resources(dest_sg_id, source_sg_id, rule):
            """For a dest SG allowing a source SG, emit edges resource<->resource."""
            dest_owners = self._resource_sg_map.get(dest_sg_id, [])
            source_owners = self._resource_sg_map.get(source_sg_id, [])
            if not dest_owners and not source_owners:
                return
            # One side may be empty (SG referenced but not attached to a known
            # resource) — still show if dest has owners.
            if not dest_owners:
                return
            # If no source owner, treat the security group itself as the source.
            if not source_owners:
                source_owners = [f"sg:{source_sg_id}"]
            for src in source_owners:
                for dst in dest_owners:
                    key = (src, dst)
                    if key in seen:
                        continue
                    seen.add(key)
                    edges.append({
                        "source": src,
                        "target": dst,
                        "label": self.port_label(rule),
                        "protocol": rule.get("protocol", "ALL"),
                        "from_port": rule.get("from_port"),
                        "to_port": rule.get("to_port"),
                        "is_issue": False,
                        "source_sg": source_sg_id,
                        "dest_sg": dest_sg_id,
                    })

        for dest_sg_id, flows in sg_flows.items():
            for flow in flows:
                resolve_flow_to_resources(dest_sg_id, flow["source_sg"], flow["rule"])

        # Cross-VPC connections (peering) -> draw a connection between the VPCs
        for peering in self.data["peering_connections"].values():
            edges.append({
                "source": peering["requester_vpc"],
                "target": peering["accepter_vpc"],
                "label": "peering",
                "protocol": "-",
                "from_port": None,
                "to_port": None,
                "is_issue": False,
                "kind": "peering",
                "id": peering["id"],
            })

        # Transit gateway edges: connect VPC nodes (proxy) — attach a TGW node
        for tgw in self.data["transit_gateways"].values():
            for att in tgw["attachments"].values():
                if att["vpc_id"]:
                    edges.append({
                        "source": att["vpc_id"],
                        "target": "tgw:" + tgw["id"],
                        "label": "tgw",
                        "protocol": "-",
                        "from_port": None,
                        "to_port": None,
                        "is_issue": False,
                        "kind": "tgw",
                    })

        self._edges = edges
        return edges

    # ------------------------------------------------------------------
    # Expose derived data
    # ------------------------------------------------------------------
    def get_routing_details(self):
        """Return route-table analysis for the report."""
        return list(self.data["route_tables"].values())

    def run(self):
        self.classify_subnets()
        nodes = self.build_resource_nodes()
        edges = self.build_edges()
        return {
            "nodes": nodes,
            "edges": edges,
            "sg_flows": self.build_sg_connectivity(),
            "subnet_classification": self._subnet_classification,
        }
