import urllib.request
from pathlib import Path

FRMR_BASE = "https://raw.githubusercontent.com/FedRAMP/docs/main/"
FRMR_FILES = [
    "FRMR.KSI.key-security-indicators.json",
    "FRMR.VDR.vulnerability-detection-and-response.json",
    "FRMR.MAS.minimum-assessment-scope.json",
    "FRMR.PVA.persistent-validation-and-assessment.json",
    "FRMR.ICP.incident-communications-procedures.json",
    "FRMR.SCN.significant-change-notifications.json",
    "FRMR.CCM.collaborative-continuous-monitoring.json",
    "FRMR.ADS.authorization-data-sharing.json",
    "FRMR.RSC.recommended-secure-configuration.json",
    "FRMR.UCM.using-cryptographic-modules.json",
    "FRMR.FSI.fedramp-security-inbox.json",
    "FRMR.FRD.fedramp-definitions.json",
]


def extract_obligations(frmr_ksi_doc) -> dict:
    """Map KSI id -> 'required' (MUST) | 'recommended' (SHOULD).

    Assumes FRMR shape: {"FRMR": {"KSI": [{"indicators": [{"id", "indicator"}]}]}}.
    Verify field names against live FedRAMP/docs after the first sync.
    """
    out = {}
    for family in frmr_ksi_doc.get("FRMR", {}).get("KSI", []):
        for indicator in family.get("indicators", []):
            text = str(indicator.get("indicator", "")).upper()
            out[indicator["id"]] = "required" if text.startswith("MUST") else "recommended"
    return out


def diff_catalog(old_doc, new_doc) -> dict:
    old = extract_obligations(old_doc)
    new = extract_obligations(new_doc)
    return {
        "added": sorted(set(new) - set(old)),
        "removed": sorted(set(old) - set(new)),
        "obligation_changed": sorted(k for k in (set(old) & set(new)) if old[k] != new[k]),
    }


def _fetch(url: str) -> str:
    with urllib.request.urlopen(url) as response:  # noqa: S310 - public FedRAMP docs
        return response.read().decode("utf-8")


def sync(dest, offline_dir=None) -> dict:
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    written = {}
    for fname in FRMR_FILES:
        if offline_dir is not None:
            source = Path(offline_dir) / fname
            if not source.exists():
                continue
            content = source.read_text()
        else:
            content = _fetch(FRMR_BASE + fname)
        (dest / fname).write_text(content)
        written[fname] = len(content)
    return written
