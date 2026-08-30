# 🗺️ vpc-archmapper

Read-only AWS **VPC network audit** and **architecture mapper**. Scans all (or
specific) regions for networking resources, analyzes how resources connect to
each other, flags common misconfigurations, and produces **three deliverables
centred on an elaborate, intuitive network architecture diagram**.

Built to satisfy the kind of client feedback: *"you didn't properly check the
route tables and the interconnection of network between all services."*

---

## ✨ Features

- **Multi-region, single-account** scanning (defaults to all regions)
- **Full network inventory**: VPCs, subnets, route tables, security groups,
  NACLs, EC2, RDS, ElastiCache, ALB/NLB, NAT gateways, IGWs, VPC endpoints,
  VPC peering, Transit Gateways
- **Connectivity analysis**: maps *which resources can talk to which*, derived
  from security group rules + cross-VPC connections
- **Misconfiguration detection**:
  - Internet-exposed SGs (`0.0.0.0/0`, `::/0`)
  - Open SSH/RDP to the internet
  - All-protocols / all-ports rules
  - Blackhole routes
  - Public/private subnet routing issues
  - Unused security groups
  - Permissive NACLs
  - Resources in the default VPC
  - Misplaced NAT gateways
- **Single unified Mermaid diagram** — VPCs, subnets, resources and their
  interconnections, with high-severity issues highlighted in red
- **Three outputs** (diagram is the primary focus):
  1. `*-diagram.html` — pure, interactive architecture diagram
  2. `*-diagram.mmd` — raw Mermaid code, importable into Excalidraw /
     Mermaid Live Editor / Mermaid Ink for editing or export
  3. `*-findings.html` — security findings & audit detail (secondary)
- **Read-only** — uses only AWS `Describe`/`List` APIs, never modifies anything

---

## ✅ IAM Permissions

Only **read-only** permissions are required, so an external auditor can run this
against the account without any write access. Attach this policy to the auditor's
IAM user/role:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "VPCNetworkAuditReadOnly",
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeRegions",
        "ec2:DescribeVpcs",
        "ec2:DescribeSubnets",
        "ec2:DescribeRouteTables",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeNetworkAcls",
        "ec2:DescribeInstances",
        "ec2:DescribeNatGateways",
        "ec2:DescribeInternetGateways",
        "ec2:DescribeVpcEndpoints",
        "ec2:DescribeVpcPeeringConnections",
        "ec2:DescribeTransitGateways",
        "ec2:DescribeTransitGatewayAttachments",
        "elasticloadbalancing:DescribeLoadBalancers",
        "rds:DescribeDBInstances",
        "elasticache:DescribeCacheClusters"
      ],
      "Resource": "*"
    }
  ]
}
```

> **Note:** If the tool lacks access to a particular service API (e.g. only VPC
> permissions but not RDS), it logs a warning and skips that section rather than
> failing — you still get a useful report for what it *can* see.

---

## 🚀 Usage

### In AWS CloudShell (recommended)

`boto3` is pre-installed and the session already has AWS credentials:

```bash
# Clone or upload the repo, then:
python3 audit.py
```

### Locally

```bash
pip install boto3     # if not already installed
python3 audit.py
```

### Options

```bash
python3 audit.py                              # all regions
python3 audit.py --region us-east-1           # single region
python3 audit.py --region us-east-1,us-west-2 # multiple regions
python3 audit.py --output ./my-report         # custom output directory
python3 audit.py --profile my-auditor         # explicit AWS CLI profile
```

The tool writes three files to the output directory (default `output/`), all
sharing a timestamp prefix (`vpc-archmap-<timestamp>`):

| File | Purpose |
|------|---------|
| `vpc-archmap-<ts>-diagram.html` | **Primary** — pure, interactive architecture diagram (pan/zoom) |
| `vpc-archmap-<ts>-diagram.mmd`  | Raw Mermaid code — import into Excalidraw, Mermaid Live Editor, Mermaid Ink |
| `vpc-archmap-<ts>-findings.html` | **Secondary** — security findings, summary, SG/route-table detail |

---

## 📂 Project Structure

```
vpc-archmapper/
├── audit.py              # Main entry point + CLI
├── lib/
│   ├── discovery.py      # AWS resource enumeration (read-only)
│   ├── analysis.py       # Connectivity graph + subnet/routing analysis
│   ├── issues.py         # Misconfiguration detection
│   ├── mermaid.py        # Mermaid diagram generation
│   └── html_report.py    # Diagram / findings / .mmd output writers
├── README.md
└── output/               # Generated deliverables
```

---

## 🖥️ Output

- **`*-diagram.html`** — open in any browser for the interactive architecture
  diagram. A tip on the page links to the raw `.mmd` file for importing into
  Excalidraw / Mermaid Live Editor.
- **`*-diagram.mmd`** — the raw Mermaid flowchart. Drag it into
  [mermaid.live](https://mermaid.live), or use Excalidraw's Mermaid plugin to
  edit/export the diagram.
- **`*-findings.html`** — summary cards, findings table (severity, resource,
  fix), security group details, and route table details.

---

## ⚠️ Disclaimer

The tool reports *likely* misconfigurations based on common best practices. It
does **not** replace a human security review. Validate findings against your
environment's actual security requirements before making changes.
