# RBVM Engine

A Python script I wrote to prioritize vulnerability findings from my home lab. It reads scanner output, looks up each CVE's EPSS score from FIRST.org, checks it against CISA's Known Exploited Vulnerabilities (KEV) catalog, and sorts everything into remediation tiers. It also groups findings that share a fix, so you get a short list of fixes instead of one row per finding.

## Why I built it

I started out triaging Nessus findings by hand, looking up EPSS and KEV for each CVE one at a time. That worked for a handful of findings, but my OpenVAS scan of Metasploitable 2 came back with 70, and real environments have thousands. CVSS tells you how bad a vulnerability could be, but not whether anyone is exploiting it, so I wanted tiers based on CVSS, EPSS and KEV together, plus a way to record my own judgment when the numbers get it wrong.

## How to run it

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python rbvm.py openvas_export.csv
```

It accepts two kinds of input:

- an OpenVAS "CSV Results" export (it detects the `NVT Name` column)
- a simple hand-written CSV with the columns `finding,cve,cvss`

With no filename it reads `findings.csv`. It writes two files:

- `tiered_findings.csv`: every finding with its tier, SLA, the CVE that decided the tier, and the reason
- `fix_plan.csv`: one row per fix, with its tier, how many findings it closes, and which ports it touches

## Tier rules

| Tier | Rule | SLA |
|---|---|---|
| 1 | On CISA KEV, or EPSS >= 90% | 24-48 hours |
| 2 | CVSS >= 8.0 and EPSS >= 10% | 14 days |
| 3 | CVSS >= 7.0 | 30-90 days |
| 4 | Everything else | Risk accepted, review quarterly |

The rules are checked in order, so a KEV-listed CVE is always Tier 1. When a finding lists several CVEs (OpenVAS often does), the worst one decides the tier: any KEV entry wins, otherwise the highest EPSS.

## Overrides

Some of the worst findings have no CVE at all, like a backdoor shell or a default password, so EPSS and KEV can't see them and the rules rank them on CVSS alone. The script flags anything with CVSS 9+ and no CVE for review. `overrides.csv` is where I record the decision:

```
match,port,tier,reason,approved_by,review_by
Possible Backdoor: Ingreslock,1524/tcp,1,Backdoor shell that gives root to anyone who connects...,Jordan Bain,2026-12-04
```

Each override keeps the original tier in the output so you can see what the rules said, and the script warns if an override no longer matches anything, since that usually means the issue was fixed and the exception should be retired.

## Fix grouping

`fix_rules.csv` maps part of a finding's name to a fix. For example, every finding starting with `SSL/TLS:` gets fixed by one config change, and rsh, rlogin and rexec all get turned off in the same place. Findings that don't match a rule still merge with copies of themselves on other ports. Each fix takes the worst tier of the findings under it.

## Results from my lab

Run on November 4, 2026 against an OpenVAS scan of Metasploitable 2 (70 findings, QoD 70 or higher):

| | Findings | Fixes |
|---|---|---|
| Tier 1 | 19 | 9 |
| Tier 2 | 2 | 2 |
| Tier 3 | 12 | 8 |
| Tier 4 | 37 | 26 |
| Total | 70 | 45 |

Two of the Tier 1 findings were on KEV (PHP-CGI CVE-2012-1823 and Tomcat Ghostcat CVE-2020-1938). One TLS configuration change closed 20 findings by itself. EPSS and KEV change daily, so a rerun will give slightly different numbers.

## What I learned

- Automating the lookup caught a finding I'd tiered too low by hand. Nessus grouped SSL v2/v3 into one plugin with no EPSS score, so I'd put POODLE in Tier 2, but its EPSS is close to 100%.
- Writing the rules as code showed a gap in my tier table: nothing covered CVSS 7.0-7.9 with EPSS above 1%, so Samba Badlock fell through.
- EPSS ranked old TLS bugs above a backdoor that gives anyone a root shell, since the backdoor has no CVE. That's why I added the review flag and overrides.
- Grouping by fix turned 19 Tier 1 findings into 9 fixes.

## Background

The findings come from Nessus Essentials and OpenVAS scans of a Windows 11 VM and a Metasploitable 2 VM, running in UTM on my Mac. Metasploitable is deliberately vulnerable, which is why the numbers are so high.

## What's next

- Asset criticality, so the same CVE ranks higher on a production server than on a test box
- Grouping by fix automatically where the scanner's solution text makes it obvious
