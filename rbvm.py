import csv
import requests

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"

TIER_SLA = {1: "24-48 hours", 2: "14 days", 3: "30-90 days", 4: "Risk accepted, review quarterly"}


def load_findings(path):
    """Read the CSV into a list of dictionaries, one per finding."""
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def load_kev():
    """Download CISA's KEV catalog and return {CVE ID: date added}."""
    response = requests.get(KEV_URL, timeout=30)
    response.raise_for_status()
    data = response.json()
    return {v["cveID"]: v["dateAdded"] for v in data["vulnerabilities"]}


def load_epss(cves):
    """Ask FIRST.org for EPSS scores and return {CVE ID: probability}."""
    response = requests.get(EPSS_URL, params={"cve": ",".join(cves)}, timeout=30)
    response.raise_for_status()
    data = response.json()
    return {row["cve"]: float(row["epss"]) for row in data["data"]}


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


def main():
    findings = load_findings("findings.csv")
    kev = load_kev()
    epss = load_epss([f["cve"] for f in findings])

    results = []
    for f in findings:
        cve = f["cve"]
        cvss = float(f["cvss"])
        score = epss.get(cve, 0.0)
        on_kev = cve in kev
        tier, reason = assign_tier(cvss, score, on_kev)
        results.append({
            "tier": tier,
            "finding": f["finding"],
            "cve": cve,
            "cvss": cvss,
            "epss": round(score, 4),
            "kev": "yes" if on_kev else "no",
            "sla": TIER_SLA[tier],
            "reason": reason,
        })

    # Most urgent first: lowest tier, then highest EPSS
    results.sort(key=lambda r: (r["tier"], -r["epss"]))

    for r in results:
        print(f"Tier {r['tier']}  {r['cve']}  EPSS {r['epss']:.4f}  {r['finding']}")
        print(f"        why: {r['reason']}  |  SLA: {r['sla']}")

    with open("tiered_findings.csv", "w", newline="") as out:
        writer = csv.DictWriter(out, fieldnames=list(results[0].keys()))
        writer.writeheader()
        writer.writerows(results)
    print("\nSaved tiered_findings.csv")


if __name__ == "__main__":
    main()
