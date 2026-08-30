"""HTML report generation for vpc-archmapper.

Wraps the Mermaid diagram and detailed audit findings into a single
self-contained HTML file that renders in any browser (Mermaid.js via CDN).
"""

import html
from datetime import datetime


SEVERITY_BADGE = {
    "high": '<span class="badge badge-high">HIGH</span>',
    "medium": '<span class="badge badge-medium">MEDIUM</span>',
    "low": '<span class="badge badge-low">LOW</span>',
    "info": '<span class="badge badge-info">INFO</span>',
}


def esc(text):
    return html.escape(str(text or ""), quote=True)


def _summary_stats(data, issues):
    stats = {
        "Regions": len(data.get("regions", [])),
        "VPCs": len(data.get("vpcs", {})),
        "Subnets": len(data.get("subnets", {})),
        "Route Tables": len(data.get("route_tables", {})),
        "Security Groups": len(data.get("security_groups", {})),
        "EC2 Instances": len(data.get("instances", {})),
        "NAT Gateways": len(data.get("nat_gateways", {})),
        "VPC Endpoints": len(data.get("vpc_endpoints", {})),
    }
    counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
    for issue in issues:
        counts[issue.severity] = counts.get(issue.severity, 0) + 1
    return stats, counts


class HTMLReport:
    def __init__(self, data, analysis, issues, mermaid_code, output_path):
        self.data = data
        self.analysis = analysis
        self.issues = issues
        self.mermaid_code = mermaid_code
        self.output_path = output_path

    def _issues_table(self):
        rows = []
        for issue in self.issues:
            rows.append(
                "<tr>"
                f"<td>{SEVERITY_BADGE.get(issue.severity, issue.severity)}</td>"
                f"<td>{esc(issue.resource)}</td>"
                f"<td>{esc(issue.title)}</td>"
                f"<td>{esc(issue.description)}</td>"
                f"<td class='mono'>{esc(issue.remediation)}</td>"
                "</tr>"
            )
        return "\n".join(rows)

    def _summary_cards(self, stats, counts):
        cards = []
        for label, value in stats.items():
            cards.append(
                f'<div class="stat"><div class="stat-value">{value}</div>'
                f'<div class="stat-label">{esc(label)}</div></div>'
            )
        cards.append(
            f'<div class="stat"><div class="stat-value issue-high">{counts["high"]}</div>'
            '<div class="stat-label">High Issues</div></div>'
        )
        cards.append(
            f'<div class="stat"><div class="stat-value issue-medium">{counts["medium"]}</div>'
            '<div class="stat-label">Medium Issues</div></div>'
        )
        cards.append(
            f'<div class="stat"><div class="stat-value issue-low">{counts["low"]}</div>'
            '<div class="stat-label">Low Issues</div></div>'
        )
        return "\n".join(cards)

    def _security_groups_section(self):
        sections = []
        for sg in self.data["security_groups"].values():
            def rules_rows(rules):
                rows = []
                for r in rules:
                    targets = ", ".join(
                        t["value"] for t in r["targets"]
                    ) or "—"
                    proto = r["protocol"]
                    if r["from_port"] is None:
                        ports = "ALL"
                    elif r["from_port"] == r["to_port"]:
                        ports = str(r["from_port"])
                    else:
                        ports = f"{r['from_port']}-{r['to_port']}"
                    rows.append(
                        f"<tr><td>{esc(proto)}</td><td>{esc(ports)}</td>"
                        f"<td>{esc(targets)}</td></tr>"
                    )
                return "\n".join(rows)

            sections.append(
                f"<details class='sg-card'><summary>"
                f"<b>{esc(sg.get('name') or sg['id'])}</b> "
                f"<span class='muted'>{esc(sg['id'])}</span>"
                f"</summary>"
                f"<div class='desc'>{esc(sg.get('description'))}</div>"
                f"<div class='sg-tables'>"
                f"<div><h4>Inbound</h4><table class='sg-table'>"
                f"<thead><tr><th>Proto</th><th>Ports</th><th>Source</th></tr></thead>"
                f"<tbody>{rules_rows(sg['ingress'])}</tbody></table></div>"
                f"<div><h4>Outbound</h4><table class='sg-table'>"
                f"<thead><tr><th>Proto</th><th>Ports</th><th>Destination</th></tr></thead>"
                f"<tbody>{rules_rows(sg['egress'])}</tbody></table></div>"
                f"</div></details>"
            )
        return "\n".join(sections)

    def _route_tables_section(self):
        sections = []
        for rt in self.data["route_tables"].values():
            header = f"<b>{esc(rt['id'])}</b>"
            vpc = self.data["vpcs"].get(rt["vpc_id"], {})
            header += f" <span class='muted'>· VPC {esc(vpc.get('name') or rt['vpc_id'])}</span>"
            subs = []
            for assoc in rt["associations"]:
                if assoc["subnet_id"]:
                    subnet = self.data["subnets"].get(assoc["subnet_id"], {})
                    subs.append(subnet.get("name") or assoc["subnet_id"])
                elif assoc["main"]:
                    subs.append("(main)")
            if subs:
                header += f" <span class='muted'>· {esc(', '.join(subs))}</span>"
            route_rows = "\n".join(
                "<tr>"
                f"<td class='mono'>{esc(r['cidr'])}</td>"
                f"<td class='mono'>{esc(r['target'])}</td>"
                f"<td>{esc(r['state'])}</td>"
                f"<td>{esc(r['target_type'])}</td>"
                "</tr>"
                for r in rt["routes"]
            )
            sections.append(
                f"<details class='sg-card'><summary>{header}</summary>"
                f"<table class='sg-table'>"
                f"<thead><tr><th>Destination</th><th>Target</th><th>State</th>"
                f"<th>Type</th></tr></thead><tbody>{route_rows}</tbody></table>"
                f"</details>"
            )
        return "\n".join(sections)

    def _errors_section(self):
        if not self.data.get("errors"):
            return ""
        items = "\n".join(f"<li>{esc(e)}</li>" for e in self.data["errors"])
        return (
            "<h2>⚠️ Discovery Warnings</h2>"
            f"<ul class='warnings'>{items}</ul>"
            "<p class='muted'>Some resources could not be enumerated due to "
            "missing permissions. Grant the full read-only policy (see README) "
            "for complete coverage.</p>"
        )

    def render(self):
        stats, counts = _summary_stats(self.data, self.issues)
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        issue_count = sum(counts.values())

        html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>VPC Architecture Map — Network Audit</title>
<script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
<style>
  :root {{
    --bg: #0f172a; --panel: #1e293b; --panel-2: #2a3a52;
    --text: #e2e8f0; --muted: #94a3b8;
    --high: #ef4444; --medium: #f59e0b; --low: #3b82f6; --info: #22d3ee;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0; font-family: -apple-system, "Segoe UI", Roboto, sans-serif;
    background: var(--bg); color: var(--text); line-height: 1.5;
  }}
  header {{
    padding: 24px 32px; background: linear-gradient(135deg,#1e3a8a,#0f172a);
    border-bottom: 1px solid #334155;
  }}
  header h1 {{ margin: 0; font-size: 24px; }}
  header .sub {{ color: var(--muted); margin-top: 4px; font-size: 13px; }}
  main {{ padding: 24px 32px; max-width: 1400px; margin: 0 auto; }}
  h2 {{ margin-top: 40px; font-size: 20px; border-bottom: 1px solid #334155;
       padding-bottom: 8px; }}
  .stats {{ display: grid; grid-template-columns: repeat(auto-fit,minmax(120px,1fr));
           gap: 16px; margin-top: 16px; }}
  .stat {{ background: var(--panel); border-radius: 10px; padding: 16px;
          text-align: center; border: 1px solid #334155; }}
  .stat-value {{ font-size: 26px; font-weight: 700; color: #60a5fa; }}
  .stat-label {{ font-size: 11px; text-transform: uppercase; letter-spacing: .5px;
                color: var(--muted); margin-top: 4px; }}
  .issue-high {{ color: var(--high); }} .issue-medium {{ color: var(--medium); }}
  .issue-low {{ color: var(--low); }}
  .diagram-box {{ background: #fff; border-radius: 12px; padding: 16px;
                 overflow-x: auto; border: 1px solid #334155; }}
  .diagram-box svg {{ max-width: 100%; }}
  .badge {{ padding: 3px 8px; border-radius: 6px; font-size: 11px;
           font-weight: 700; color: #fff; }}
  .badge-high {{ background: var(--high); }}
  .badge-medium {{ background: var(--medium); color: #1e293b; }}
  .badge-low {{ background: var(--low); }}
  .badge-info {{ background: var(--info); color: #1e293b; }}
  table {{ border-collapse: collapse; width: 100%; }}
  th, td {{ border: 1px solid #334155; padding: 8px 10px; text-align: left;
           font-size: 13px; vertical-align: top; }}
  th {{ background: var(--panel-2); }}
  tr:nth-child(even) td {{ background: #16213a; }}
  .mono {{ font-family: ui-monospace, SFMono-Regular, monospace; }}
  .sg-card {{ background: var(--panel); border: 1px solid #334155;
             border-radius: 10px; margin-bottom: 12px; overflow: hidden; }}
  .sg-card summary {{ padding: 12px 16px; cursor: pointer; font-size: 14px; }}
  .sg-card summary:hover {{ background: var(--panel-2); }}
  .desc {{ padding: 0 16px 8px; color: var(--muted); font-size: 13px; }}
  .sg-tables {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px;
               padding: 0 16px 16px; }}
  .sg-table {{ margin-top: 8px; }}
  .sg-table h4 {{ margin: 8px 0 4px; font-size: 13px; color: var(--muted); }}
  .muted {{ color: var(--muted); font-weight: 400; font-size: 12px; }}
  .warnings {{ list-style: none; padding: 0; }}
  .warnings li {{ background: #3b2f2f; border: 1px solid #7f1d1d; color: #fca5a5;
                 border-radius: 8px; padding: 10px 14px; margin-bottom: 8px;
                 font-size: 13px; }}
  footer {{ padding: 24px 32px; color: var(--muted); font-size: 12px;
            border-top: 1px solid #334155; margin-top: 48px; }}
  details[open] summary {{ border-bottom: 1px solid #334155; }}
  @media print {{
    body {{ background: #fff; color: #000; }}
    .diagram-box {{ border: 1px solid #ccc; }}
    header {{ background: #fff; color: #000; border-bottom: 1px solid #ccc; }}
    table, .sg-card {{ border-color: #ccc; }}
    th, td {{ border-color: #ccc; }}
    tr:nth-child(even) td {{ background: #f3f4f6; }}
  }}
</style>
</head>
<body>
<header>
  <h1>🗺️ VPC Architecture Map — Network Audit Report</h1>
  <div class="sub">Generated {now} · {len(self.data.get('regions', []))} region(s) ·
  {issue_count} issue(s) found · vpc-archmapper</div>
</header>
<main>
  <h2>📊 Summary</h2>
  <div class="stats">{self._summary_cards(stats, counts)}</div>

  <h2>🏗️ Architecture Diagram</h2>
  <p class="muted">Interactive map of VPCs, subnets, resources and their
  connectivity. <b>Red nodes/edges</b> highlight high-severity findings.
  Pan and zoom with your mouse or trackpad.</p>
  <div class="diagram-box">
    <pre class="mermaid">
{self.mermaid_code}
    </pre>
  </div>

  <h2>🔍 Findings</h2>
  <table>
    <thead><tr><th>Severity</th><th>Resource</th><th>Finding</th>
    <th>Details</th><th>Recommendation</th></tr></thead>
    <tbody>{self._issues_table()}</tbody>
  </table>

  <h2>🔒 Security Groups</h2>
  {self._security_groups_section()}

  <h2>🗺️ Route Tables</h2>
  {self._route_tables_section()}

  {self._errors_section()}
</main>
<footer>
  Generated by <b>vpc-archmapper</b> — read-only VPC network audit tool.
  Review findings and validate against your security requirements before
  making changes.
</footer>
<script>
  mermaid.initialize({{
    startOnLoad: true,
    theme: 'base',
    themeVariables: {{
      fontFamily: 'ui-monospace, SFMono-Regular, monospace',
      fontSize: '13px',
      primaryColor: '#e0f2fe',
      primaryTextColor: '#0f172a',
      lineColor: '#475569',
      edgeLabelBackground: '#f8fafc',
      clusterBkg: '#ffffff',
      clusterBorder: '#cbd5e1',
    }},
    securityLevel: 'loose',
    flowchart: {{ curve: 'linear', htmlLabels: true }},
  }});
</script>
</body>
</html>"""
        with open(self.output_path, "w", encoding="utf-8") as f:
            f.write(html_doc)
        return self.output_path
