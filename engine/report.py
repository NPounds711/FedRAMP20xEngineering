import csv


def load_ksi_index(path):
    rows = []
    with open(path, newline="") as fh:
        for row in csv.DictReader(fh):
            rows.append({
                "ksi": row["KSI_ID"].strip(),
                "obligation": (row.get("Obligation") or "required").strip().lower(),
            })
    return rows


def coverage(ksi_index, determinations):
    addressed = set()
    for d in determinations:
        if d["result"] == "pass":
            for k in d["frameworks"]["fedramp-20x"]:
                addressed.add(k["ksi"])
    total = len(ksi_index)
    required = [k for k in ksi_index if k["obligation"] == "required"]
    recommended = [k for k in ksi_index if k["obligation"] == "recommended"]
    req_addr = [k for k in required if k["ksi"] in addressed]
    rec_addr = [k for k in recommended if k["ksi"] in addressed]
    pct = (len(addressed) / total * 100) if total else 0.0
    gaps = [k for k in ksi_index if k["ksi"] not in addressed]
    gaps.sort(key=lambda k: 0 if k["obligation"] == "required" else 1)
    return {
        "total_ksis": total,
        "automated_pct": round(pct, 1),
        "meets_70_threshold": pct >= 70.0,
        "required_addressed": f"{len(req_addr)}/{len(required)}",
        "recommended_addressed": f"{len(rec_addr)}/{len(recommended)}",
        "gaps": [{"ksi": k["ksi"], "obligation": k["obligation"]} for k in gaps],
    }
