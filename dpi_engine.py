#!/usr/bin/env python3
"""
dpi_engine.py – Command-line entry point for the Python DPI engine.

Usage:
  python dpi_engine.py <input.pcap> <output.pcap> [options]

Options:
  --block-app  <name>    Block an application (e.g. YouTube, TikTok)
  --block-ip   <ip>      Block all traffic from source IP
  --block-domain <kw>    Block any SNI/Host containing this keyword

Examples:
  python dpi_engine.py test_dpi.pcap output.pcap
  python dpi_engine.py test_dpi.pcap output.pcap --block-app YouTube --block-ip 192.168.1.50
  python dpi_engine.py test_dpi.pcap output.pcap --block-domain tiktok --block-domain facebook
"""

import argparse
import sys
from pathlib import Path

# Make sure the package is importable when running from the project root
sys.path.insert(0, str(Path(__file__).parent.parent))

from DPI import DPIEngine, RuleManager, print_report


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="dpi_engine.py",
        description="Python Deep Packet Inspection Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("input",  help="Input pcap file")
    p.add_argument("output", help="Output pcap file (allowed packets)")
    p.add_argument("--block-app",    metavar="NAME",    action="append",
                   default=[], dest="block_apps",
                   help="Block application (e.g. YouTube)")
    p.add_argument("--block-ip",     metavar="IP",      action="append",
                   default=[], dest="block_ips",
                   help="Block source IP address")
    p.add_argument("--block-domain", metavar="KEYWORD", action="append",
                   default=[], dest="block_domains",
                   help="Block SNI/Host containing keyword")
    return p


def main():
    sys.stdout.reconfigure(encoding='utf-8')
    args = build_arg_parser().parse_args()

    # ------------------------------------------------------------------ banner
    w = 66
    print(f"\n╔{'═' * w}╗")
    print(f"║{'DPI ENGINE v2.0 (Python)':^{w}}║")
    print(f"╚{'═' * w}╝\n")

    # ------------------------------------------------------------------ rules
    rules = RuleManager()
    for app in args.block_apps:
        rules.block_app(app)
    for ip in args.block_ips:
        rules.block_ip(ip)
    for kw in args.block_domains:
        rules.block_domain(kw)

    print()

    # ------------------------------------------------------------------ run
    engine = DPIEngine(rules=rules)
    try:
        stats = engine.run(args.input, args.output)
    except FileNotFoundError as e:
        print(f"\n[ERROR] {e}")
        sys.exit(1)
    except ValueError as e:
        print(f"\n[ERROR] {e}")
        sys.exit(1)

    # ------------------------------------------------------------------ report
    print_report(stats, rules)
    print(f"Output written to: {args.output}\n")


if __name__ == "__main__":
    main()
