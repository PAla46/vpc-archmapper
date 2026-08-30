"""Mermaid flowchart generation for vpc-archmapper.

Turns the abstract resource graph into a single unified Mermaid flowchart,
nested by VPC and subnet, with connectivity edges and issue highlighting.
"""

import re

# Node styling per resource type
TYPE_STYLE = {
    "ec2": "fill:#3b82f6,stroke:#1d4ed8,color:#fff",
    "elb": "fill:#8b5cf6,stroke:#6d28d9,color:#fff",
    "rds": "fill:#10b981,stroke:#047857,color:#fff",
    "cache": "fill:#f59e0b,stroke:#b45309,color:#fff",
    "nat": "fill:#6366f1,stroke:#4338ca,color:#fff",
    "vpc-endpoint": "fill:#14b8a6,stroke:#0f766e,color:#fff",
    "tgw": "fill:#ef4444,stroke:#b91c1c,color:#fff",
}

TYPE_ICON = {
    "ec2": "🖥️",
    "elb": "⚖️",
    "rds": "🗄️",
    "cache": "⚡",
    "nat": "🔁",
    "vpc-endpoint": "🔌",
    "tgw": "🔀",
    "igw": "🌐",
}


def _esc(text):
    """Escape characters that break Mermaid node/label definitions."""
    if text is None:
        return ""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _nid(text):
    """Build a Mermaid-safe node id (alphanumeric + underscore only).

    AWS resource ids contain hyphens; Mermaid ids must not. Hash-suffix isn't
    needed because AWS ids are already globally unique after sanitization when
    we preserve digits/letters.
    """
    safe = re.sub(r"[^A-Za-z0-9]", "_", str(text))
    return safe


class MermaidGenerator:
    def __init__(self, data, analysis, issues=()):
        self.data = data
        self.analysis = analysis
        self.issues = list(issues)
        self._issue_sg_map = self._build_issue_sg_map()

    def _build_issue_sg_map(self):
        """Map high-severity issue resource names so we can color affected
        nodes red."""
        result = {}
        for issue in self.issues:
            if issue.severity == "high":
                result.setdefault(issue.resource, "high")
        return result

    # ------------------------------------------------------------------
    def _vpc_color(self, index):
        palette = [
            "#e0f2fe",  # sky
            "#fce7f3",  # pink
            "#d1fae5",  # emerald
            "#fef3c7",  # amber
            "#ede9fe",  # violet
            "#dbeafe",  # blue
            "#fde68a",  # yellow
            "#cffafe",  # cyan
        ]
        return palette[index % len(palette)]

    # ------------------------------------------------------------------
    def _node_decl(self, nid, label, extra_sg="", extra="", style=None):
        inner = f"<b>{_esc(label)}</b>"
        if extra:
            inner += f"<br/><span style='font-size:9px'>{_esc(extra)}</span>"
        if extra_sg:
            inner += (
                "<br/><span style='font-size:8px'>SG: "
                + _esc(extra_sg)
                + "</span>"
            )
        return f'{nid}["{inner}"]'

    # ------------------------------------------------------------------
    def _igw_label(self, igw):
        return "🌐 Internet Gateway " + (igw["id"] if igw["id"] else "")

    def _route_label(self, rt):
        dests = []
        for r in rt["routes"]:
            if r.get("is_local") and r.get("state") == "active":
                continue
            dests.append(r.get("cidr", "?") + " → " + r.get("target", "?"))
        if not dests:
            return f"RT {rt['id']}"
        return f"RT {rt['id']} · " + ", ".join(dests)

    # ------------------------------------------------------------------
    def generate(self):
        """Return the raw Mermaid flowchart markup (no markdown fences).

        Fences are intentionally omitted: the consumer decides presentation.
        The HTML page embeds this raw text in a `<pre class="mermaid">` block,
        and the `.mmd` file ships it verbatim for Excalidraw / Mermaid Live.
        """
        lines = ["graph TB"]
        declared_nodes = set()

        igw_by_vpc = {}
        for igw in self.data["internet_gateways"].values():
            igw_by_vpc.setdefault(igw["vpc_id"], []).append(igw)

        rt_by_vpc = {}
        for rt in self.data["route_tables"].values():
            rt_by_vpc.setdefault(rt["vpc_id"], []).append(rt)

        for i, vpc in enumerate(self.data["vpcs"].values()):
            vnode = "VPC_" + _nid(vpc["id"])
            vlabel = f"{vpc['name'] or vpc['id']} ({vpc['cidr']})"
            color = self._vpc_color(i)

            vpc_nodes = [
                (nid, node)
                for nid, node in self.analysis._resource_nodes.items()
                if node.get("vpc_id") == vpc["id"]
            ]
            vpc_igws = igw_by_vpc.get(vpc["id"], [])
            vpc_rts = rt_by_vpc.get(vpc["id"], [])

            # Skip VPCs that have nothing to render — avoids empty boxes and
            # keeps the diagram clean/valid.
            if not vpc_nodes and not vpc_igws and not vpc_rts:
                continue

            lines.append(
                f'    subgraph {vnode}["{_esc(vlabel)}"]'
            )
            lines.append(
                f'        style {vnode} fill:{color},stroke:#94a3b8,'
                "stroke-width:1px"
            )

            # Resource nodes grouped by subnet.
            subnet_groups = {}
            for nid, node in vpc_nodes:
                key = node.get("subnet_id") or "NONE"
                subnet_groups.setdefault(key, []).append((nid, node))

            def group_sort_key(item):
                key, nodes_list = item
                if key == "NONE":
                    return (3, key)
                node = nodes_list[0][1]
                return (0 if node.get("is_public") else 1, key)

            for key, group in sorted(subnet_groups.items(), key=group_sort_key):
                node = group[0][1]
                if key == "NONE":
                    for nid, n in group:
                        self._emit_node(lines, nid, n, indent=2)
                        declared_nodes.add(nid)
                    continue

                subnet = self.data["subnets"].get(key, {})
                snode = "SN_" + _nid(key)
                public_tag = "🔓 Public" if node.get("is_public") else "🔒 Private"
                subnet_label = f"{subnet.get('name') or subnet['id']} · {public_tag}"
                lines.append(f'        subgraph {snode}["{_esc(subnet_label)}"]')
                lines.append(
                    "            style " + snode + " fill:#ffffff,stroke:#cbd5e1"
                )
                for nid, n in group:
                    self._emit_node(lines, nid, n, indent=3)
                    declared_nodes.add(nid)
                lines.append("        end")

            # Internet gateways — nest inside their VPC so it isn't an empty box
            # and the VPC's internet attachment is visible.
            for igw in vpc_igws:
                igw_id = "IGW_" + _nid(igw["id"])
                if igw_id not in declared_nodes:
                    lines.append(f'        {igw_id}["{self._igw_label(igw)}"]')
                    lines.append(
                        "        style " + igw_id
                        + " fill:#0ea5e9,stroke:#0369a1,color:#fff"
                    )
                    declared_nodes.add(igw_id)

            # Route tables — the client explicitly wanted routings checked, so
            # surface them as visible nodes inside the VPC.
            for rt in vpc_rts:
                rt_id = "RT_" + _nid(rt["id"])
                if rt_id in declared_nodes:
                    continue
                declared_nodes.add(rt_id)
                lines.append(f'        {rt_id}["{self._route_label(rt)}"]')
                lines.append(
                    "        style " + rt_id
                    + " fill:#f8fafc,stroke:#94a3b8,color:#334155"
                )

            lines.append("    end")

        # Transit gateways
        for tgw in self.data["transit_gateways"].values():
            tgd_id = "Tgw_" + _nid(tgw["id"])
            label = TYPE_ICON["tgw"] + " " + tgw["id"]
            lines.append(f'    {tgd_id}["{label}"]')
            lines.append(
                f"    style {tgd_id} fill:#7f1d1d,stroke:#450a0a,color:#fff"
            )
            declared_nodes.add(tgd_id)

        # Connectivity edges
        edge_lines = []
        seen_edges = set()

        for edge in self.analysis._edges:
            src = edge["source"]
            dst = edge["target"]

            if edge.get("kind") == "peering":
                src_id = "VPC_" + _nid(src)
                dst_id = "VPC_" + _nid(dst)
                if src_id in declared_nodes and dst_id in declared_nodes:
                    ekey = f"{src_id}|{dst_id}"
                    if ekey not in seen_edges:
                        seen_edges.add(ekey)
                        edge_lines.append(
                            f'    {src_id} -.->|"🔗 peering {_esc(edge.get("id", ""))}"| '
                            f"{dst_id}"
                        )
                continue

            if edge.get("kind") == "tgw":
                vpc_id, tgw_id = src, dst[4:]
                vpc_proxy = "VPC_" + _nid(vpc_id)
                tgw_proxy = "Tgw_" + _nid(tgw_id)
                if vpc_proxy in declared_nodes and tgw_proxy in declared_nodes:
                    ekey = f"{vpc_proxy}|{tgw_proxy}"
                    if ekey not in seen_edges:
                        seen_edges.add(ekey)
                        edge_lines.append(
                            f'    {vpc_proxy} -.->|"🔀 TGW"| {tgw_proxy}'
                        )
                continue

            src_id = _nid(src)
            dst_id = _nid(dst)
            src_label = self._label_for(src)
            dst_label = self._label_for(dst)

            ekey = f"{src_id}|{dst_id}|{edge.get('label', '')}"
            if ekey in seen_edges:
                continue
            seen_edges.add(ekey)

            if self._is_issue_edge(edge):
                edge_lines.append(
                    f'    {src_id} ==>|"{_esc(edge["label"])} — {_esc(src_label)} '
                    f"→ {_esc(dst_label)}\"| {dst_id}"
                )
            else:
                edge_lines.append(
                    f'    {src_id} -->|"{_esc(edge["label"])} — {_esc(src_label)} '
                    f"→ {_esc(dst_label)}\"| {dst_id}"
                )

        lines.extend(edge_lines)
        return "\n".join(lines)

    # ------------------------------------------------------------------
    def _emit_node(self, lines, nid, node, indent=2):
        pad = "    " * indent
        safe_id = _nid(nid)
        icon = TYPE_ICON.get(node.get("type"), "❓")
        label = node.get("label") or node.get("id") or nid
        extra = node.get("extra", "")

        sg_list = node.get("sg_ids", [])
        sg_names = []
        has_high = False
        for sid in sg_list:
            sg = self.data["security_groups"].get(sid, {})
            sg_names.append(sg.get("name") or sid)
            if self._issue_sg_map.get(sg.get("name") or sid) == "high":
                has_high = True

        style = TYPE_STYLE.get(node.get("type"), "fill:#94a3b8,stroke:#64748b,color:#fff")
        if has_high:
            style = "fill:#ef4444,stroke:#7f1d1d,color:#fff"

        inner = f"<b>{icon} {_esc(label)}</b>"
        if extra:
            inner += f"<br/><span style='font-size:9px'>{_esc(extra)}</span>"
        if sg_names:
            inner += (
                "<br/><span style='font-size:8px'>SG: "
                + _esc(", ".join(sg_names))
                + "</span>"
            )

        lines.append(f'{pad}{safe_id}["{inner}"]')
        lines.append(f"{pad}style {safe_id} {style}")

    # ------------------------------------------------------------------
    def _label_for(self, node_key):
        if node_key in self.analysis._resource_nodes:
            n = self.analysis._resource_nodes[node_key]
            return n.get("label") or n.get("id") or node_key
        if node_key.startswith("sg:"):
            sg = self.data["security_groups"].get(node_key[3:], {})
            return sg.get("name") or node_key[3:]
        return node_key

    def _is_issue_edge(self, edge):
        dest_sg = self.data["security_groups"].get(edge.get("dest_sg", ""), {})
        name = dest_sg.get("name") or dest_sg.get("id", "")
        return self._issue_sg_map.get(name) == "high"
