"""Output report generation for vpc-archmapper.

Writes three separate deliverables focused on the architecture diagram as the
primary output, with findings as a secondary artifact and the raw Mermaid code
as an importable file (Excalidraw, Mermaid Live Editor, etc.):
  1. <base>-diagram.html  - pure, interactive architecture diagram only
  2. <base>-findings.html - the security findings report (secondary)
  3. <base>-diagram.mmd   - raw Mermaid markup, fully importable
"""

import html
import os
from datetime import datetime

SEVERITY_BADGE = {
    "high": '<span class="badge badge-high">HIGH</span>',
    "medium": '<span class="badge badge-medium">MEDIUM</span>',
    "low": '<span class="badge badge-low">LOW</span>',
    "info": '<span class="badge badge-info">INFO</span>',
}

# Shared look & feel for all HTML outputs.
_CSS = """
  :root {
    --bg: #0f172a; --panel: #1e293b; --panel-2: #2a3a52;
    --text: #e2e8f0; --muted: #94a3b8;
    --high: #ef4444; --medium: #f59e0b; --low: #3b82f6; --info: #22d3ee;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; font-family: -apple-system, "Segoe UI", Roboto, sans-serif;
    background: var(--bg); color: var(--text); line-height: 1.5;
  }
  header {
    padding: 24px 32px; background: linear-gradient(135deg,#1e3a8a,#0f172a);
    border-bottom: 1px solid #334155;
  }
  header h1 { margin: 0; font-size: 24px; }
  header .sub { color: var(--muted); margin-top: 4px; font-size: 13px; }
  main { padding: 24px 32px; max-width: 1400px; margin: 0 auto; }
  h2 { margin-top: 40px; font-size: 20px; border-bottom: 1px solid #334155;
       padding-bottom: 8px; }
  .stats { display: grid; grid-template-columns: repeat(auto-fit,minmax(120px,1fr));
           gap: 16px; margin-top: 16px; }
  .stat { background: var(--panel); border-radius: 10px; padding: 16px;
          text-align: center; border: 1px solid #334155; }
  .stat-value { font-size: 26px; font-weight: 700; color: #60a5fa; }
  .stat-label { font-size: 11px; text-transform: uppercase; letter-spacing: .5px;
                color: var(--muted); margin-top: 4px; }
  .issue-high { color: var(--high); } .issue-medium { color: var(--medium); }
  .issue-low { color: var(--low); }
  .diagram-box { position: relative; background: #fff; border-radius: 12px;
                 overflow: hidden; border: 1px solid #334155;
                 height: calc(100vh - 300px); min-height: 480px; }
  .diagram-box svg { width: 100%; height: 100%; display: block; cursor: grab; }
  .diagram-box svg.panning { cursor: grabbing; }
  .zoom-controls { position: absolute; top: 10px; right: 10px; z-index: 10;
                   display: flex; flex-direction: column; gap: 6px; }
  .zoom-controls button { width: 36px; height: 36px; border-radius: 8px;
       border: 1px solid #334155; background: #fff; color: #0f172a;
       font-size: 18px; font-weight: 700; cursor: pointer; line-height: 1;
       box-shadow: 0 2px 6px rgba(0,0,0,.25); }
  .zoom-controls button:hover { background: #e2e8f0; }
  .zoom-hint { position: absolute; bottom: 10px; left: 50%; transform: translateX(-50%);
       z-index: 10; font-size: 12px; color: #475569; background: rgba(255,255,255,.9);
       padding: 4px 10px; border-radius: 999px; border: 1px solid #cbd5e1;
       box-shadow: 0 1px 4px rgba(0,0,0,.15); }
  .badge { padding: 3px 8px; border-radius: 6px; font-size: 11px;
           font-weight: 700; color: #fff; }
  .badge-high { background: var(--high); }
  .badge-medium { background: var(--medium); color: #1e293b; }
  .badge-low { background: var(--low); }
  .badge-info { background: var(--info); color: #1e293b; }
  table { border-collapse: collapse; width: 100%; }
  th, td { border: 1px solid #334155; padding: 8px 10px; text-align: left;
           font-size: 13px; vertical-align: top; }
  th { background: var(--panel-2); }
  tr:nth-child(even) td { background: #16213a; }
  .mono { font-family: ui-monospace, SFMono-Regular, monospace; }
  .muted { color: var(--muted); font-weight: 400; font-size: 12px; }
  .tip { background: var(--panel); border: 1px solid #334155; border-radius: 10px;
         padding: 14px 18px; margin-top: 20px; font-size: 13px; color: var(--muted); }
  .tip code { background: var(--panel-2); padding: 1px 5px; border-radius: 4px; }
  .sg-card { background: var(--panel); border: 1px solid #334155;
             border-radius: 10px; margin-bottom: 12px; overflow: hidden; }
  .sg-card summary { padding: 12px 16px; cursor: pointer; font-size: 14px; }
  .sg-card summary:hover { background: var(--panel-2); }
  .sg-card[open] summary { border-bottom: 1px solid #334155; }
  .desc { padding: 0 16px 8px; color: var(--muted); font-size: 13px; }
  .sg-tables { display: grid; grid-template-columns: 1fr 1fr; gap: 16px;
               padding: 0 16px 16px; }
  .sg-table { margin-top: 8px; }
  .warnings { list-style: none; padding: 0; }
  .warnings li { background: #3b2f2f; border: 1px solid #7f1d1d; color: #fca5a5;
                 border-radius: 8px; padding: 10px 14px; margin-bottom: 8px;
                 font-size: 13px; }
  footer { padding: 24px 32px; color: var(--muted); font-size: 12px;
            border-top: 1px solid #334155; margin-top: 48px; }
  .empty { color: var(--muted); font-size: 13px; }
  @media print {
    body { background: #fff; color: #000; }
    .diagram-box { border: 1px solid #ccc; }
    header { background: #fff; color: #000; border-bottom: 1px solid #ccc; }
    table { border-color: #ccc; }
    th, td { border-color: #ccc; }
    tr:nth-child(even) td { background: #f3f4f6; }
  }
"""

_MERMAID_CONFIG = """
  mermaid.initialize({
    startOnLoad: false,
    theme: 'base',
    themeVariables: {
      fontFamily: 'ui-monospace, SFMono-Regular, monospace',
      fontSize: '13px',
      primaryColor: '#e0f2fe',
      primaryTextColor: '#0f172a',
      lineColor: '#475569',
      edgeLabelBackground: '#f8fafc',
      clusterBkg: '#ffffff',
      clusterBorder: '#cbd5e1',
    },
    securityLevel: 'loose',
    flowchart: { curve: 'linear', htmlLabels: true },
  });
"""

# Interactive diagram script: renders the mermaid diagram, then wires up
# svg-pan-zoom for drag-to-pan and mouse-wheel/touch zoom, plus +/-/reset
# controls.
_INTERACTIVE_INIT = """
  mermaid.run({ querySelector: '.mermaid' }).then(function() {
    var box = document.querySelector('.diagram-box');
    var svg = box && box.querySelector('svg');
    if (!svg || typeof svgPanZoom === 'undefined') return;

    var pan = svgPanZoom(svg, {
      zoomEnabled: true,
      controlIconsEnabled: false,
      fit: true,
      contain: false,
      center: true,
      minZoom: 0.2,
      maxZoom: 15,
      dblClickZoomEnabled: true,
      mouseWheelZoomEnabled: true,
      preventMouseEventsDefault: false,
    });
    svg.addEventListener('mousedown', function(){ svg.classList.add('panning'); });
    svg.addEventListener('mouseup', function(){ svg.classList.remove('panning'); });

    document.getElementById('zoom-in').addEventListener('click', function(){ pan.zoomIn(); });
    document.getElementById('zoom-out').addEventListener('click', function(){ pan.zoomOut(); });
    document.getElementById('zoom-reset').addEventListener('click', function(){ pan.reset(); });
  });
"""


def esc(text):
    return html.escape(str(text or ""), quote=True)


def _page(title, sub, body, active_scripts=True, interactive=False):
    scripts = ""
    if active_scripts:
        scripts = (
            '<script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>'
        )
        if interactive:
            scripts += (
                '<script src="https://cdn.jsdelivr.net/npm/svg-pan-zoom@3.6.1/'
                'dist/svg-pan-zoom.min.js"></script>'
            )
    # Only run a script when the relevant CDN/CDNs are actually loaded.
    init_script = ""
    if active_scripts:
        if interactive:
            init_script = (
                "<script>\n" + _MERMAID_CONFIG + "\n" + _INTERACTIVE_INIT + "\n</script>"
            )
        else:
            init_script = f"<script>\n{_MERMAID_CONFIG}\n</script>"
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(title)}</title>
{scripts}
<style>
{_CSS}
</style>
</head>
<body>
<header>
  <h1>{esc(title)}</h1>
  <div class="sub">{esc(sub)}</div>
</header>
<main>
{body}
</main>
<footer>
  Generated by <b>vpc-archmapper</b> — read-only VPC network audit tool.
</footer>
{init_script}
</body>
</html>"""


class ReportWriter:
    """Writes the three vpc-archmapper output files."""

    def __init__(self, data, analysis, issues, mermaid_code):
        self.data = data
        self.analysis = analysis
        self.issues = issues
        self.mermaid_code = mermaid_code

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------
    def _summary_stats(self):
        stats = {
            "Regions": len(self.data.get("regions", [])),
            "VPCs": len(self.data.get("vpcs", {})),
            "Subnets": len(self.data.get("subnets", {})),
            "Route Tables": len(self.data.get("route_tables", {})),
            "Security Groups": len(self.data.get("security_groups", {})),
            "EC2 Instances": len(self.data.get("instances", {})),
            "NAT Gateways": len(self.data.get("nat_gateways", {})),
            "VPC Endpoints": len(self.data.get("vpc_endpoints", {})),
        }
        counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
        for issue in self.issues:
            counts[issue.severity] = counts.get(issue.severity, 0) + 1
        return stats, counts

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

    def _now(self):
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def _region_summary(self):
        return f"{len(self.data.get('regions', []))} region(s)"

    # ------------------------------------------------------------------
    # 1. PURE DIAGRAM (primary output)
    # ------------------------------------------------------------------
    def render_diagram_html(self, path, mmd_path):
        """Write a minimal HTML page containing only the interactive diagram."""
        mmd_name = os.path.basename(mmd_path)
        body = f"""
  <h2>🏗️ Architecture Diagram</h2>
  <p class="muted">Interactive map of VPCs, subnets, resources and their
  connectivity. <b>Red nodes/edges</b> highlight high-severity findings.
  <b>Drag</b> to pan and use the <b>mouse wheel</b> or the buttons to zoom.</p>
  <div class="diagram-box">
    <div class="zoom-controls">
      <button id="zoom-in" title="Zoom in" aria-label="Zoom in">+</button>
      <button id="zoom-out" title="Zoom out" aria-label="Zoom out">−</button>
      <button id="zoom-reset" title="Reset view" aria-label="Reset view">⟲</button>
    </div>
    <pre class="mermaid">
{self.mermaid_code}
    </pre>
    <div class="zoom-hint">Drag to pan · scroll to zoom · buttons to control</div>
  </div>
  <div class="tip">
    💡 <b>Import into other tools:</b> the raw diagram code is shipped alongside
    this page as <code>{esc(mmd_name)}</code>. Open it in the
    <a href="https://mermaid.live">Mermaid Live Editor</a>, Mermaid Ink, or
    Excalidraw (via the Mermaid plugin) to edit or export the diagram.
  </div>
"""
        doc = _page(
            "VPC Architecture Diagram",
            f"Generated {self._now()} · {self._region_summary()} · vpc-archmapper",
            body,
            active_scripts=True,
            interactive=True,
        )
        _write(doc, path)
        return path

    # ------------------------------------------------------------------
    # 2. FINDINGS (secondary output)
    # ------------------------------------------------------------------
    def render_findings_html(self, path):
        """Write the security findings report (issues) as its own page."""
        stats, counts = self._summary_stats()
        issue_count = sum(counts.values())
        body = f"""
  <h2>📊 Summary</h2>
  <div class="stats">{self._summary_cards(stats, counts)}</div>

  <h2>🔍 Findings ({issue_count})</h2>
  {self._issues_table()}

  {self._warnings_section()}
  {self._route_tables_section()}
  {self._sg_section()}
"""
        doc = _page(
            "VPC Architecture Audit — Findings",
            f"Generated {self._now()} · {self._region_summary()} · {issue_count} issue(s) · vpc-archmapper",
            body,
            active_scripts=False,
        )
        _write(doc, path)
        return path

    def _issues_table(self):
        if not self.issues:
            return "<p class='empty'>No issues detected.</p>"
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
        return (
            "<table><thead><tr><th>Severity</th><th>Resource</th><th>Finding</th>"
            "<th>Details</th><th>Recommendation</th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table>"
        )

    def _warnings_section(self):
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

    def _route_tables_section(self):
        if not self.data.get("route_tables"):
            return ""
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
        return "<h2>🗺️ Route Tables</h2>" + "\n".join(sections)

    def _sg_section(self):
        if not self.data.get("security_groups"):
            return ""
        sections = []
        for sg in self.data["security_groups"].values():
            def rules_rows(rules):
                rows = []
                for r in rules:
                    targets = ", ".join(t["value"] for t in r["targets"]) or "—"
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
        return "<h2>🔒 Security Groups</h2>" + "\n".join(sections)

    # ------------------------------------------------------------------
    # 3. RAW MERMAID CODE (importable)
    # ------------------------------------------------------------------
    def render_mermaid_code(self, path):
        """Write a raw .mmd file containing only the Mermaid flowchart markup.

        The markup ships fence-free (the generator emits raw Mermaid), so the
        file is directly importable into the Mermaid Live Editor, Mermaid Ink,
        and Excalidraw (via its Mermaid plugin).
        """
        code = self.mermaid_code.strip()
        # Defensive: strip any markdown fences that may have slipped through.
        if code.startswith("```"):
            code = code.split("\n", 1)[1] if "\n" in code else ""
        if code.rstrip().endswith("```"):
            code = code.rstrip()[:-3].rstrip()
        _write(code + "\n", path)
        return path


def _write(content, path):
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
