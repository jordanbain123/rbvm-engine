# RBVM Engine

A small Python script I wrote to prioritize vulnerability findings from my home lab. It takes a list of CVEs, looks up each one's EPSS score from FIRST.org, checks whether it's on CISA's Known Exploited Vulnerabilities (KEV) list, and sorts everything into remediation tiers.

## Why I built it

I was triaging Nessus findings by hand, looking up EPSS and KEV for each CVE one at a time. It was slow, and I wanted to know if my manual calls held up. CVSS tells you how bad a vulnerability could be, but not whether anyone is actually exploiting it, so I wanted my tiers based on all three.

## Tier rules

| Tier | Rule | SLA |
|---|---|---|
| 1 | On CISA KEV, or EPSS >= 90% | 24-48 hours |
| 2 | CVSS >= 8.0 and EPSS >= 10% | 14 days |
| 3 | CVSS >= 7.0 | 30-90 days |
| 4 | Everything else | Risk accepted, review quarterly |

The rules are checked in order, so a KEV-listed CVE is always Tier 1. Each result includes the reason it got its tier.

## How to run it

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python rbvm.py
```

Input is `findings.csv` with the columns `finding,cve,cvss`. Output is `tiered_findings.csv`, sorted most urgent first.

## Results from my lab

| Tier | Finding | CVE | CVSS | EPSS | KEV |
|---|---|---|---|---|---|
| 1 | SSL v3 POODLE | CVE-2014-3566 | 9.8 | ~1.0 | no |
| 1 | WinVerifyTrust signature validation | CVE-2013-3900 | 8.8 | 0.4465 | yes |
| 2 | Debian OpenSSL RNG weakness | CVE-2008-0166 | 10.0 | 0.7072 | no |
| 3 | Samba Badlock | CVE-2016-2118 | 7.5 | 0.3693 | no |

EPSS changes daily, so these numbers are from October 22, 2026.

## What I learned

The first run disagreed with me. Nessus reported SSL v2/v3 as one grouped plugin with no EPSS score, so I'd put it in Tier 2 based on context. When the script looked up the POODLE CVE directly, its EPSS was close to 100%, which makes it Tier 1 under my own rules.

Turning my tier table into code also showed it had a gap. A CVE with CVSS between 7.0 and 7.9 and EPSS above 1% didn't match any tier. Samba Badlock fell right through it, so I had to decide where those go.

It was also a good reminder that CVSS isn't the whole story. The CVSS 10.0 finding ended up ranked below a CVSS 8.8 one, because the 8.8 is on the KEV list.

## Background

The findings come from Nessus Essentials scans of a Windows 11 VM and a Metasploitable 2 VM running in UTM on my Mac. Some lab findings, like a planted bind shell and a default VNC password, don't have CVEs, so I tiered those by hand.

## What's next

- Asset criticality, so the same CVE ranks higher on a production server than on a test box
- Manual overrides for findings without a CVE
- Reading OpenVAS exports instead of a hand-typed CSV
