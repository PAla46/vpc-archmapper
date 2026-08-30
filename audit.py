#!/usr/bin/env python3
"""vpc-archmapper — Read-only AWS VPC network audit and architecture mapper.

Scans all (or specified) regions for VPC networking resources, analyzes
connectivity between resources, flags common misconfigurations, and produces
three deliverables centred on the architecture diagram:

  1. <ts>-diagram.html  - pure, interactive Mermaid architecture diagram (primary)
  2. <ts>-diagram.mmd   - raw Mermaid code, importable into Excalidraw /
                          Mermaid Live Editor / Mermaid Ink
  3. <ts>-findings.html - security findings & audit detail (secondary)

Requires read-only IAM permissions only. Runs natively in AWS CloudShell
(boto3 is pre-installed) or locally with `pip install boto3`.

Usage:
    python3 audit.py
    python3 audit.py --region us-east-1
    python3 audit.py --output ./my-report
    python3 audit.py --profile my-profile --region us-east-1,us-west-2
"""

import argparse
import os
import sys
from datetime import datetime

try:
    import boto3
    from botocore.exceptions import NoCredentialsError, ProfileNotFound
except ImportError:  # pragma: no cover
    print(
        "ERROR: boto3 is required. In AWS CloudShell it is pre-installed.\n"
        "Locally, run:  pip install boto3\n",
        file=sys.stderr,
    )
    sys.exit(2)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lib.discovery import AWSDiscovery  # noqa: E402
from lib.analysis import NetworkAnalyzer  # noqa: E402
from lib.issues import IssueDetector  # noqa: E402
from lib.mermaid import MermaidGenerator  # noqa: E402
from lib.html_report import ReportWriter  # noqa: E402

BANNER = r"""
=====================================================================
  vpc-archmapper — AWS VPC Network Audit & Architecture Mapper
  Read-only. No resources are modified.
=====================================================================
"""


def parse_args():
    parser = argparse.ArgumentParser(
        description="Audit AWS VPC networking and generate an architecture map."
    )
    parser.add_argument(
        "--region",
        help="Comma-separated list of regions, e.g. us-east-1,us-west-2. "
        "Defaults to all regions.",
    )
    parser.add_argument(
        "--output",
        default="output",
        help="Output directory (default: ./output). Writes three files: "
        "<ts>-diagram.html (pure diagram), <ts>-diagram.mmd (raw Mermaid code), "
        "and <ts>-findings.html (security findings).",
    )
    parser.add_argument(
        "--profile",
        default=None,
        help="AWS CLI profile name to use (instead of default credentials).",
    )
    return parser.parse_args()


def resolve_regions(region_arg):
    if not region_arg:
        return None
    regions = [r.strip() for r in region_arg.split(",") if r.strip()]
    return regions or None


def main():
    print(BANNER)
    args = parse_args()

    # Build a boto3 session
    try:
        session = boto3.Session(profile_name=args.profile)
    except ProfileNotFound:
        print(
            f"ERROR: AWS profile '{args.profile}' not found.\n"
            "Configure credentials with 'aws configure' or check your "
            "~/.aws/credentials.",
            file=sys.stderr,
        )
        sys.exit(1)
    except (NoCredentialsError, ValueError) as exc:
        print(f"ERROR: Could not create AWS session: {exc}", file=sys.stderr)
        sys.exit(1)

    try:
        session.client("sts").get_caller_identity()
    except NoCredentialsError:
        print(
            "ERROR: No AWS credentials found. Configure them via environment "
            "variables, ~/.aws/credentials, or an IAM role (CloudShell).",
            file=sys.stderr,
        )
        sys.exit(1)
    except Exception as exc:
        # AccessDenied may appear here for policy-only setups; still try.
        print(f"NOTE: Could not verify identity ({exc}). Continuing anyway.")

    regions = resolve_regions(args.region)

    discovery = AWSDiscovery(session=session, regions=regions)
    data = discovery.run()

    if not data["vpcs"]:
        print(
            "\nNo VPCs were discovered. This may mean AWS credentials were not "
            "set up correctly, or the account has no VPCs in the scanned regions.",
            file=sys.stderr,
        )
        if data["errors"]:
            print("\nDiscovery warnings:")
            for e in data["errors"]:
                print(f"  - {e}")
        sys.exit(1)

    print(f"  VPCs found: {len(data['vpcs'])}")
    print(f"  Regions scanned: {len(data['regions'])}")

    print("Analyzing connectivity and routing...")
    analyzer = NetworkAnalyzer(data)
    analysis = analyzer.run()

    print("Detecting misconfigurations...")
    detector = IssueDetector(data, analyzer)
    issues = detector.run()
    print(f"  Issues found: {len(issues)}")

    print("Generating Mermaid diagram...")
    mermaid = MermaidGenerator(data, analyzer, issues)
    mermaid_code = mermaid.generate()

    os.makedirs(args.output, exist_ok=True)
    base = os.path.join(args.output, f"vpc-archmap-{datetime.now().strftime('%Y%m%d-%H%M%S')}")

    diagram_html = f"{base}-diagram.html"
    findings_html = f"{base}-findings.html"
    mermaid_file = f"{base}-diagram.mmd"

    writer = ReportWriter(data, analyzer, issues, mermaid_code)

    print("Writing diagram (primary output)...")
    writer.render_diagram_html(diagram_html, mermaid_file)

    print("Writing raw Mermaid code...")
    writer.render_mermaid_code(mermaid_file)

    print("Writing findings (secondary output)...")
    writer.render_findings_html(findings_html)

    print("\n" + "=" * 69)
    print("  ✓ Audit complete!")
    print(f"  Regions: {', '.join(data['regions'])}")
    print(f"  VPCs:    {len(data['vpcs'])}")
    print(f"  Issues:  {len(issues)}"
          f" (high={sum(1 for i in issues if i.severity=='high')},"
          f" medium={sum(1 for i in issues if i.severity=='medium')},"
          f" low={sum(1 for i in issues if i.severity=='low')})")
    print("=" * 69)
    print("\nDeliverables:")
    print(f"  🏗️  Diagram (primary):  {os.path.abspath(diagram_html)}")
    print(f"  🔀 Mermaid code:       {os.path.abspath(mermaid_file)}")
    print(f"  🔍 Findings (secondary): {os.path.abspath(findings_html)}")
    print("\nOpen the diagram HTML in a browser. Import the .mmd file into "
          "Mermaid Live Editor / Excalidraw to edit or export.")


if __name__ == "__main__":
    main()
