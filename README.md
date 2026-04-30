# cors-checker

![Python](https://img.shields.io/badge/python-3.10+-blue.svg) ![License](https://img.shields.io/badge/license-MIT-green.svg) ![Last Commit](https://img.shields.io/github/last-commit/TaoTheReaper/cors-checker) ![CI](https://github.com/TaoTheReaper/cors-checker/actions/workflows/ci.yml/badge.svg)


Test web applications for CORS misconfigurations.

## Features

- Tests **wildcard** (`*`) ACAO header
- Tests **reflected origin** (server mirrors attacker origin)
- Tests **null origin** (sandboxed iframe attack)
- Tests subdomain variant origins (`evil.target.com`, `target.com.attacker.com`…)
- Detects **CRITICAL** when reflected origin + `Access-Control-Allow-Credentials: true`
- Generates **PoC fetch() snippet** for critical findings
- JSON report output

## Install

```bash
pip install -r requirements.txt
```

## Usage

```bash
# Basic test
python cors-checker.py https://api.example.com/user

# Add custom origin
python cors-checker.py https://example.com/api --origin https://my-evil.com

# Save JSON report
python cors-checker.py https://example.com/api -o cors-report.json -v
```

## Severity levels

| Finding | Severity |
|---------|----------|
| Reflected origin + credentials | CRITICAL |
| Reflected origin | HIGH |
| null origin accepted | HIGH |
| Wildcard `*` | MEDIUM |

## Legal notice

Use only against systems you own or have written authorisation to test.
