import json
import uuid as uuidlib

_NS = uuidlib.UUID("12345678-1234-5678-1234-567812345678")


def _uid(name: str) -> str:
    return str(uuidlib.uuid5(_NS, name))


def render(determinations, timestamp=None) -> str:
    determinations = list(determinations)
    ts = timestamp or (determinations[0]["collected_at"] if determinations else "1970-01-01T00:00:00Z")
    findings = []
    for d in determinations:
        controls = list(d["frameworks"].get("nist-800-53-rev5", []))
        findings.append({
            "uuid": _uid("finding:" + d["capability"]),
            "title": d.get("title", d["capability"]),
            "target": {
                "type": "objective-id",
                "target-id": d["capability"],
                "status": {"state": "satisfied" if d["result"] == "pass" else "not-satisfied"},
            },
            "related-controls": {
                "control-selections": [
                    {"include-controls": [{"control-id": c} for c in controls]}
                ]
            },
            "props": [
                {"name": "evidence-hash", "ns": "https://fedramp.gov/ns/20x", "value": d["evidence_ref"]}
            ],
        })
    doc = {
        "assessment-results": {
            "uuid": _uid("assessment-results"),
            "metadata": {
                "title": "FedRAMP20x Automated Evidence",
                "version": "1.0.0",
                "oscal-version": "1.2.0",
                "last-modified": ts,
            },
            "import-ap": {"href": "#"},
            "results": [
                {
                    "uuid": _uid("result"),
                    "title": "Automated evidence collection",
                    "start": ts,
                    "findings": findings,
                }
            ],
        }
    }
    return json.dumps(doc, indent=2, sort_keys=True)
