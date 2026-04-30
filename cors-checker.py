#!/usr/bin/env python3
"""cors-checker — test for CORS misconfigurations."""

import argparse
import json
import logging
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    import requests
except ImportError:
    print("[!] Missing: pip install requests")
    sys.exit(1)

log = logging.getLogger("cors-checker")

C = {
    "red": "\033[91m", "green": "\033[92m", "yellow": "\033[93m",
    "cyan": "\033[96m", "bold": "\033[1m", "reset": "\033[0m"
}

EVIL_ORIGINS = [
    "https://evil.com",
    "https://attacker.com",
    "null",
]

def setup_logging(verbose: bool):
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.WARNING,
        format="%(asctime)s [%(levelname)s] %(message)s"
    )

def test_origin(url: str, origin: str, with_creds: bool = False) -> dict:
    headers = {
        "Origin": origin,
        "User-Agent": "Mozilla/5.0",
    }
    if with_creds:
        headers["Cookie"] = "session=test"

    try:
        resp = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
        acao  = resp.headers.get("Access-Control-Allow-Origin", "")
        acac  = resp.headers.get("Access-Control-Allow-Credentials", "")
        acam  = resp.headers.get("Access-Control-Allow-Methods", "")
        acah  = resp.headers.get("Access-Control-Allow-Headers", "")
        vary  = resp.headers.get("Vary", "")

        result = {
            "origin_sent":   origin,
            "acao":          acao,
            "acac":          acac,
            "acam":          acam,
            "acah":          acah,
            "vary":          vary,
            "status":        resp.status_code,
            "vulnerable":    False,
            "finding":       None,
        }

        # Check vulnerabilities
        if acao == "*":
            result["finding"]   = "Wildcard ACAO — any origin allowed"
            result["vulnerable"] = True
            result["severity"]   = "MEDIUM"

        elif acao == origin and origin != "null":
            result["finding"]   = f"Origin reflected: {origin}"
            result["vulnerable"] = True
            result["severity"]   = "HIGH"
            if acac.lower() == "true":
                result["finding"]  += " + credentials allowed"
                result["severity"]  = "CRITICAL"

        elif acao == "null" or origin == "null" and acao == "null":
            result["finding"]   = "null origin accepted — sandboxed iframe attack possible"
            result["vulnerable"] = True
            result["severity"]   = "HIGH"

        elif acao and acao != "":
            result["finding"]   = f"Fixed ACAO: {acao} (not reflected)"
            result["vulnerable"] = False
            result["severity"]   = "INFO"

        else:
            result["finding"]   = "No CORS headers returned"
            result["vulnerable"] = False
            result["severity"]   = "INFO"

        log.debug("Origin=%s → ACAO=%s ACAC=%s", origin, acao, acac)
        return result

    except requests.exceptions.ConnectionError:
        return {"origin_sent": origin, "error": "connection refused", "vulnerable": False}
    except requests.exceptions.Timeout:
        return {"origin_sent": origin, "error": "timeout", "vulnerable": False}
    except Exception as e:
        return {"origin_sent": origin, "error": str(e), "vulnerable": False}

def test_subdomain_origins(url: str, target_domain: str) -> list[dict]:
    """Test if subdomain origins of the target domain are trusted."""
    parsed = re.sub(r"https?://", "", target_domain).rstrip("/")
    sub_origins = [
        f"https://evil.{parsed}",
        f"https://evil-{parsed}",
        f"https://{parsed}.attacker.com",
        f"https://not{parsed}",
    ]
    results = []
    for origin in sub_origins:
        r = test_origin(url, origin)
        if r.get("vulnerable"):
            results.append(r)
    return results

def print_results(url: str, results: list[dict], sub_results: list[dict]):
    print(C["cyan"] + f"\n{'='*60}")
    print(f"  CORS CHECKER — {url}")
    print(f"{'='*60}" + C["reset"])

    vulns = [r for r in results if r.get("vulnerable")]
    clean = [r for r in results if not r.get("vulnerable") and "error" not in r]

    if vulns or sub_results:
        print(f"\n{C['red']}{C['bold']}⚠ VULNERABILITIES FOUND{C['reset']}\n")
        for r in vulns + sub_results:
            sev = r.get("severity", "HIGH")
            sc  = C["red"] if sev in ("CRITICAL", "HIGH") else C["yellow"]
            print(f"  {sc}[{sev}]{C['reset']} Origin: {r['origin_sent']}")
            print(f"         Finding : {r['finding']}")
            print(f"         ACAO    : {r.get('acao')}")
            print(f"         ACAC    : {r.get('acac') or '(not set)'}")
            if sev == "CRITICAL":
                print(f"         {C['red']}PoC: fetch('{url}', {{credentials:'include'}}) from {r['origin_sent']}{C['reset']}")
            print()
    else:
        print(f"\n{C['green']}  No CORS vulnerabilities detected.{C['reset']}")

    print(f"{C['green']}All test results:{C['reset']}")
    for r in results:
        if "error" in r:
            print(f"  ⚠ {r['origin_sent']:<40} ERROR: {r['error']}")
        elif r.get("vulnerable"):
            print(f"  {C['red']}✗ {r['origin_sent']:<40} {r['finding']}{C['reset']}")
        else:
            print(f"  {C['green']}✓ {r['origin_sent']:<40} {r.get('finding','')}{C['reset']}")

    print(C["cyan"] + f"\n{'='*60}" + C["reset"])

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cors-checker",
        description="Test for CORS misconfigurations — reflected origins, wildcard, credentials.",
        epilog=(
            "Examples:\n"
            "  python cors-checker.py https://example.com/api/user\n"
            "  python cors-checker.py https://api.example.com -o report.json\n"
            "  python cors-checker.py https://example.com --origin https://custom-evil.com"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("url",              help="Target URL to test")
    p.add_argument("--origin",         metavar="ORIGIN", help="Additional origin to test")
    p.add_argument("-o", "--output",   metavar="FILE",   help="Save JSON report")
    p.add_argument("-v", "--verbose",  action="store_true")
    return p

def main():
    parser = build_parser()
    args = parser.parse_args()
    setup_logging(args.verbose)

    url = args.url
    origins = list(EVIL_ORIGINS)
    if args.origin:
        origins.insert(0, args.origin)

    # also reflect the actual origin as trusted domain variant
    domain = re.sub(r"https?://([^/]+).*", r"\1", url)
    origins.append(f"https://{domain}")

    print(f"{C['cyan']}[*] Testing {len(origins)} origins on {url}...{C['reset']}")
    results     = [test_origin(url, o) for o in origins]
    sub_results = test_subdomain_origins(url, domain)

    print_results(url, results, sub_results)

    if args.output:
        report = {
            "url":       url,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "results":   results,
            "subdomain_results": sub_results,
        }
        tmp = args.output + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False, default=str)
        os.replace(tmp, args.output)
        print(f"{C['green']}[+] Report saved: {args.output}{C['reset']}")

if __name__ == "__main__":
    main()
