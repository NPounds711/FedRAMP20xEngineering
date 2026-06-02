import urllib.error
import urllib.request
from pathlib import Path

FRMR_BASE = "https://raw.githubusercontent.com/FedRAMP/docs/main/"
FETCH_TIMEOUT = 30
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
    Verify field names against live FedRAMP/docs after the first sync. Indicators
    without an "id" are skipped rather than raising.
    """
    out = {}
    for family in frmr_ksi_doc.get("FRMR", {}).get("KSI", []):
        for indicator in family.get("indicators", []):
            ksi_id = indicator.get("id")
            if not ksi_id:
                continue
            text = str(indicator.get("indicator", "")).upper()
            out[ksi_id] = "required" if text.startswith("MUST") else "recommended"
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
    with urllib.request.urlopen(url, timeout=FETCH_TIMEOUT) as response:  # noqa: S310 - public FedRAMP docs
        return response.read().decode("utf-8")


def sync(dest, offline_dir=None) -> dict:
    """Sync FRMR files into dest.

    Returns {"written": {filename: byte_count}, "failed": {filename: error}}.
    In online mode a fetch failure is recorded under "failed" and does NOT abort
    the run (so one bad file can't silently leave a half-updated catalog). In
    offline mode, files absent from offline_dir are skipped silently.
    """
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    written = {}
    failed = {}
    for fname in FRMR_FILES:
        try:
            if offline_dir is not None:
                source = Path(offline_dir) / fname
                if not source.exists():
                    continue
                content = source.read_text()
            else:
                content = _fetch(FRMR_BASE + fname)
        except (urllib.error.URLError, OSError) as exc:
            failed[fname] = str(exc)
            continue
        (dest / fname).write_text(content)
        written[fname] = len(content)
    return {"written": written, "failed": failed}
