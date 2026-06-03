import json
from pathlib import Path

import yaml


def extract_ksis(frmr_doc) -> dict:
    """Flatten the KSI section of a consolidated FRMR doc.

    Returns {ksi_id: {"family", "statement", "fka": str|None, "controls": sorted[str]}}.
    """
    out = {}
    for family, fam_obj in (frmr_doc.get("KSI", {}) or {}).items():
        for ksi_id, ind in (fam_obj.get("indicators", {}) or {}).items():
            out[ksi_id] = {
                "family": family,
                "statement": str(ind.get("statement", "")).strip(),
                "fka": ind.get("fka"),
                "controls": sorted(ind.get("controls", []) or []),
            }
    return out
