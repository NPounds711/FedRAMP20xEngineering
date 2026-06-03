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


def load_slice_ksis(slices_dir) -> dict:
    """Map each KSI id referenced by a slice's mapping.yaml to the slice name(s)."""
    out = {}
    for mapping in sorted(Path(slices_dir).glob("*/mapping.yaml")):
        data = yaml.safe_load(mapping.read_text()) or {}
        for k in data.get("ksis", []):
            out.setdefault(k["id"], []).append(mapping.parent.name)
    return out


def affected(diff, slice_ksis) -> list:
    """One record per (change, slice) where a change touches a KSI a slice maps to.

    Only `renamed` is auto_fixable; removals/restatements/control changes need a human.
    """
    items = []
    for r in diff["renamed"]:
        for s in slice_ksis.get(r["old"], []):
            items.append({"slice": s, "ksi": r["old"], "change": "renamed",
                          "detail": r["new"], "auto_fixable": True})
    for change in ("removed", "restated", "controls_changed"):
        for ksi in diff[change]:
            for s in slice_ksis.get(ksi, []):
                items.append({"slice": s, "ksi": ksi, "change": change,
                              "detail": "", "auto_fixable": False})
    return items


def diff_ksis(old, new) -> dict:
    """Structured diff between two extract_ksis() results.

    A rename is a NEW indicator whose `fka` names an id that was in OLD and is no
    longer a current id in NEW. Rename source/target are excluded from removed/added.
    """
    old_ids, new_ids = set(old), set(new)
    renamed, renamed_old, renamed_new = [], set(), set()
    for nid, n in new.items():
        fka = n.get("fka")
        if fka and fka in old_ids and fka not in new_ids:
            renamed.append({"old": fka, "new": nid})
            renamed_old.add(fka)
            renamed_new.add(nid)
    common = old_ids & new_ids
    return {
        "added": sorted(new_ids - old_ids - renamed_new),
        "removed": sorted(old_ids - new_ids - renamed_old),
        "renamed": sorted(renamed, key=lambda r: r["old"]),
        "restated": sorted(i for i in common if old[i]["statement"] != new[i]["statement"]),
        "controls_changed": sorted(i for i in common if old[i]["controls"] != new[i]["controls"]),
    }
