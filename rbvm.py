import csv
import os
import sys

import requests

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"

# the EPSS api takes a comma separated list in the url, so I send CVEs in
# chunks instead of all ~120 at once
EPSS_BATCH = 50

SLA = {1: "24-48 hours", 2: "14 days", 3: "30-90 days", 4: "Risk accepted, review quarterly"}


def load_findings(path):
    # works with my original hand-typed findings.csv (finding,cve,cvss)
    # and with the "CSV Results" export from OpenVAS
    findings = []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        is_openvas = "NVT Name" in (reader.fieldnames or [])

        for row in reader:
            if is_openvas:
                # one finding can list several CVEs: "CVE-2008-5304,CVE-2008-5305"
                cves = [c.strip() for c in row["CVEs"].split(",") if c.strip()]
                port = f"{row['Port']}/{row['Port Protocol']}" if row["Port"] else "general"
                findings.append({
                    "finding": row["NVT Name"],
                    "host": row["IP"],
                    "port": port,
                    "cvss": float(row["CVSS"] or 0),
                    "cves": cves,
                })
            else:
                findings.append({
                    "finding": row["finding"],
                    "host": "",
                    "port": "",
                    "cvss": float(row["cvss"]),
                    "cves": [row["cve"]] if row["cve"] else [],
                })
    return findings


def get_kev():
    r = requests.get(KEV_URL, timeout=30)
    r.raise_for_status()
    return {v["cveID"]: v["dateAdded"] for v in r.json()["vulnerabilities"]}


def get_epss(cves):
    cves = sorted(set(cves))
    scores = {}
    for i in range(0, len(cves), EPSS_BATCH):
        chunk = cves[i:i + EPSS_BATCH]
        r = requests.get(EPSS_URL, params={"cve": ",".join(chunk)}, timeout=30)
        r.raise_for_status()
        for row in r.json()["data"]:
            scores[row["cve"]] = float(row["epss"])
    return scores


def pick_tier(cvss, epss, on_kev):
    # same order as my tier table, so KEV always wins
    if on_kev:
        return 1, "On CISA KEV (actively exploited)"
    if epss >= 0.90:
        return 1, f"EPSS {epss:.2%} >= 90%"
    if cvss >= 8.0 and epss >= 0.10:
        return 2, f"CVSS {cvss} >= 8.0 and EPSS {epss:.2%} >= 10%"
    # my original table had no rule for CVSS 7-7.9 with EPSS over 1%
    # (Samba Badlock fell through), so tier 3 catches any CVSS >= 7
    if cvss >= 7.0:
        return 3, f"CVSS {cvss} >= 7.0"
    return 4, f"CVSS {cvss} < 7.0"


def score(f, kev, epss):
    # no CVE means no EPSS or KEV data, so this only goes off CVSS.
    # backdoors and default passwords end up here and get under-ranked,
    # which is why the high ones get flagged for review
    if not f["cves"]:
        tier, reason = pick_tier(f["cvss"], 0.0, False)
        review = "yes" if f["cvss"] >= 9.0 else "no"
        return tier, "", 0.0, False, reason + " (no CVE, no EPSS/KEV data)", review

    # if a finding has more than one CVE, the worst one decides the tier
    on_kev = [c for c in f["cves"] if c in kev]
    top = max(f["cves"], key=lambda c: epss.get(c, 0.0))
    top_epss = epss.get(top, 0.0)

    tier, reason = pick_tier(f["cvss"], top_epss, bool(on_kev))
    worst = on_kev[0] if on_kev else top
    if on_kev:
        reason = f"{worst} on CISA KEV (actively exploited)"
    return tier, worst, top_epss, bool(on_kev), reason, "no"


def load_overrides(path="overrides.csv"):
    if not os.path.exists(path):
        return []
    with open(path, newline="", encoding="utf-8") as f:
        rows = [r for r in csv.DictReader(f)
                if r.get("match", "").strip() and not r["match"].startswith("#")]
    for r in rows:
        r["tier"] = int(r["tier"])
    return rows


def apply_overrides(results, overrides):
    # match is part of the finding name, port is optional
    used = set()
    for r in results:
        for i, o in enumerate(overrides):
            if o["match"].strip().lower() not in r["finding"].lower():
                continue
            if o.get("port", "").strip() and o["port"].strip() != r["port"]:
                continue

            r["original_tier"] = r["tier"]
            r["tier"] = o["tier"]
            r["sla"] = SLA[o["tier"]]
            r["override"] = "yes"
            r["needs_context_review"] = "reviewed"
            r["reason"] = (f"Override by {o.get('approved_by', '?')} (review by {o.get('review_by', '?')}): "
                           f"{o['reason']}. Rules said tier {r['original_tier']}")
            used.add(i)
            break

    # an override that matches nothing is probably fixed or out of date
    unused = [o["match"] for i, o in enumerate(overrides) if i not in used]
    return len(used), unused


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "findings.csv"
    findings = load_findings(path)
    kev = get_kev()
    epss = get_epss([c for f in findings for c in f["cves"]])
    print(f"{len(findings)} findings from {path}, {len(kev)} CVEs on KEV\n")

    results = []
    for f in findings:
        tier, cve, top_epss, on_kev, reason, review = score(f, kev, epss)
        results.append({
            "tier": tier,
            "finding": f["finding"],
            "host": f["host"],
            "port": f["port"],
            "cvss": f["cvss"],
            "cve_count": len(f["cves"]),
            "driver_cve": cve,
            "epss": round(top_epss, 4),
            "kev": "yes" if on_kev else "no",
            "sla": SLA[tier],
            "needs_context_review": review,
            "reason": reason,
            "original_tier": tier,
            "override": "no",
        })

    overrides = load_overrides()
    applied, unused = apply_overrides(results, overrides)
    print(f"Overrides applied: {applied}/{len(overrides)}")
    for name in unused:
        print(f"  warning: no finding matched override '{name}'")
    print()

    # overrides go first within a tier, otherwise a backdoor with no EPSS
    # sorts below every TLS finding
    results.sort(key=lambda r: (r["tier"], r["override"] != "yes", -r["epss"], -r["cvss"]))

    for t in (1, 2, 3, 4):
        print(f"Tier {t}: {sum(r['tier'] == t for r in results)}")
    left = sum(r["needs_context_review"] == "yes" for r in results)
    print(f"Still need review (CVSS 9+, no CVE): {left}\n")

    for r in results[:15]:
        star = "*" if r["override"] == "yes" else " "
        print(f"Tier {r['tier']}{star} EPSS {r['epss']:.4f}  {r['driver_cve'] or '-':<15} {r['finding'][:55]}")
    print("(* = manual override)")

    with open("tiered_findings.csv", "w", newline="") as out:
        writer = csv.DictWriter(out, fieldnames=list(results[0].keys()))
        writer.writeheader()
        writer.writerows(results)
    print("\nwrote tiered_findings.csv")

    # TODO: asset criticality (same CVE should rank higher on a prod box)
    # TODO: group findings that share one fix, like all the old TLS settings


if __name__ == "__main__":
    main()
