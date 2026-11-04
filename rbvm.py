import csv
import sys
import requests

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
EPSS_BATCH = 50  # CVEs per EPSS request, to keep the URL a safe length

TIER_SLA = {1: "24-48 hours", 2: "14 days", 3: "30-90 days", 4: "Risk accepted, review quarterly"}


def load_findings(path):
    """Read either the original findings.csv or an OpenVAS 'CSV Results' export.

    Every finding comes back in the same shape:
    {"finding", "host", "port", "cvss", "cves": [list of CVE IDs]}
    """
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        columns = reader.fieldnames or []
        findings = []
        for row in reader:
            if "NVT Name" in columns:  # OpenVAS export
                cves = [c.strip() for c in row["CVEs"].split(",") if c.strip()]
                findings.append({
                    "finding": row["NVT Name"],
                    "host": row["IP"],
                    "port": f"{row['Port']}/{row['Port Protocol']}" if row["Port"] else "general",
                    "cvss": float(row["CVSS"] or 0),
                    "cves": cves,
                })
            else:  # original hand-typed format: finding,cve,cvss
                findings.append({
                    "finding": row["finding"],
                    "host": "",
                    "port": "",
                    "cvss": float(row["cvss"]),
                    "cves": [row["cve"]] if row["cve"] else [],
                })
    return findings


def load_kev():
    """Download CISA's KEV catalog and return {CVE ID: date added}."""
    response = requests.get(KEV_URL, timeout=30)
    response.raise_for_status()
    return {v["cveID"]: v["dateAdded"] for v in response.json()["vulnerabilities"]}


def load_epss(cves):
    """Ask FIRST.org for EPSS scores in batches and return {CVE ID: probability}."""
    cves = sorted(set(cves))
    scores = {}
    for i in range(0, len(cves), EPSS_BATCH):
        batch = cves[i:i + EPSS_BATCH]
        response = requests.get(EPSS_URL, params={"cve": ",".join(batch)}, timeout=30)
        response.raise_for_status()
        for row in response.json()["data"]:
            scores[row["cve"]] = float(row["epss"])
    return scores


def assign_tier(cvss, epss, on_kev):
    """Apply the roadmap's Tier 1-4 rules. Returns (tier, reason)."""
    if on_kev:
        return 1, "On CISA KEV (actively exploited)"
    if epss >= 0.90:
        return 1, f"EPSS {epss:.2%} >= 90%"
    if cvss >= 8.0 and epss >= 0.10:
        return 2, f"CVSS {cvss} >= 8.0 and EPSS {epss:.2%} >= 10%"
    if cvss >= 7.0:
        return 3, f"CVSS {cvss} >= 7.0"
    return 4, f"CVSS {cvss} < 7.0"


def score_finding(f, kev, epss):
    """Tier one finding using its worst CVE: any KEV entry wins, else the highest EPSS."""
    if not f["cves"]:
        tier, reason = assign_tier(f["cvss"], 0.0, False)
        needs_review = "yes" if f["cvss"] >= 9.0 else "no"
        return tier, "", 0.0, False, reason + " (no CVE, so no EPSS/KEV data)", needs_review

    kev_hits = [c for c in f["cves"] if c in kev]
    top_cve = max(f["cves"], key=lambda c: epss.get(c, 0.0))
    top_epss = epss.get(top_cve, 0.0)
    driver = kev_hits[0] if kev_hits else top_cve
    tier, reason = assign_tier(f["cvss"], top_epss, bool(kev_hits))
    if kev_hits:
        reason = f"{driver} on CISA KEV (actively exploited)"
    return tier, driver, top_epss, bool(kev_hits), reason, "no"


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "findings.csv"
    findings = load_findings(path)
    kev = load_kev()
    epss = load_epss([c for f in findings for c in f["cves"]])
    print(f"Loaded {len(findings)} findings from {path} and {len(kev)} KEV entries\n")

    results = []
    for f in findings:
        tier, driver, top_epss, on_kev, reason, needs_review = score_finding(f, kev, epss)
        results.append({
            "tier": tier,
            "finding": f["finding"],
            "host": f["host"],
            "port": f["port"],
            "cvss": f["cvss"],
            "cve_count": len(f["cves"]),
            "driver_cve": driver,
            "epss": round(top_epss, 4),
            "kev": "yes" if on_kev else "no",
            "sla": TIER_SLA[tier],
            "needs_context_review": needs_review,
            "reason": reason,
        })

    # Most urgent first: lowest tier, then highest EPSS, then highest CVSS
    results.sort(key=lambda r: (r["tier"], -r["epss"], -r["cvss"]))

    for tier in (1, 2, 3, 4):
        print(f"Tier {tier}: {sum(r['tier'] == tier for r in results)} findings")
    flagged = [r for r in results if r["needs_context_review"] == "yes"]
    print(f"Needs context review (CVSS >= 9.0, no CVE): {len(flagged)}\n")

    for r in results[:15]:
        print(f"Tier {r['tier']}  EPSS {r['epss']:.4f}  {r['driver_cve'] or '-':<15} {r['finding'][:55]}")

    with open("tiered_findings.csv", "w", newline="") as out:
        writer = csv.DictWriter(out, fieldnames=list(results[0].keys()))
        writer.writeheader()
        writer.writerows(results)
    print("\nSaved tiered_findings.csv")


if __name__ == "__main__":
    main()
