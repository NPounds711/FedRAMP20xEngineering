def render(determinations) -> str:
    lines = ["# FedRAMP Evidence Summary", ""]
    for d in determinations:
        ksis = ", ".join(
            f"{k['ksi']} ({k['obligation']})" for k in d["frameworks"]["fedramp-20x"]
        )
        controls = ", ".join(d["frameworks"]["nist-800-53-rev5"])
        status = "PASS" if d["result"] == "pass" else "FAIL"
        lines += [
            f"## {d.get('title', d['capability'])} — {status}",
            f"- Capability: `{d['capability']}`",
            f"- 20x KSIs: {ksis or 'none'}",
            f"- Rev 5 controls: {controls or 'none'}",
            f"- Evidence hash: `{d['evidence_ref']}`",
            f"- Collected at: {d['collected_at']}",
        ]
        if d["result"] != "pass" and d.get("violations"):
            lines.append(f"- Violations: {'; '.join(map(str, d['violations']))}")
        lines.append("")
    return "\n".join(lines)
