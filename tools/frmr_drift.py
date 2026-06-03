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


def draft_mapping_edits(affected_items, slices_dir, apply=False) -> list:
    """For renames only, substitute old->new KSI id in the slice's mapping.yaml.
    Returns the edits; applies them in place when apply=True. Non-renames are ignored."""
    edits = []
    for item in affected_items:
        if item["change"] != "renamed" or not item["auto_fixable"]:
            continue
        path = Path(slices_dir) / item["slice"] / "mapping.yaml"
        edits.append({"path": str(path), "old": item["ksi"], "new": item["detail"]})
        if apply:
            path.write_text(path.read_text().replace(item["ksi"], item["detail"]))
    return edits


def summarize(diff, affected_items) -> str:
    """Human-readable PR body: change counts + auto-drafted vs needs-decision lists."""
    lines = [
        "## FRMR auto-sync",
        "",
        (f"Changes: {len(diff['added'])} added, {len(diff['removed'])} removed, "
         f"{len(diff['renamed'])} renamed, {len(diff['restated'])} restated, "
         f"{len(diff['controls_changed'])} control-set changes."),
        "",
    ]
    auto = [a for a in affected_items if a["auto_fixable"]]
    manual = [a for a in affected_items if not a["auto_fixable"]]
    if auto:
        lines += ["### Auto-drafted in this PR (id renames)"]
        lines += [f"- `{a['slice']}`: `{a['ksi']}` → `{a['detail']}`" for a in auto] + [""]
    if manual:
        lines += ["### ⚠️ Needs your decision (not auto-applied)"]
        lines += [f"- `{a['slice']}`: `{a['ksi']}` was **{a['change']}**" for a in manual] + [""]
    if not affected_items:
        lines += ["No shipped slice is affected; this PR only refreshes the catalog."]
    return "\n".join(lines)


def run(catalog_path, slices_dir, new_doc) -> dict:
    """Diff a fetched FRMR doc against the committed catalog snapshot. Pure: writes nothing."""
    catalog_path = Path(catalog_path)
    old_doc = json.loads(catalog_path.read_text()) if catalog_path.exists() else {"KSI": {}}
    diff = diff_ksis(extract_ksis(old_doc), extract_ksis(new_doc))
    changed = any(diff[k] for k in diff)
    aff = affected(diff, load_slice_ksis(slices_dir))
    return {"changed": changed, "diff": diff, "affected": aff, "summary": summarize(diff, aff)}


def _load_doc(offline_doc):
    if offline_doc:
        return json.loads(Path(offline_doc).read_text())
    from tools.sync import DOC_FILE, FRMR_BASE, _fetch
    return json.loads(_fetch(FRMR_BASE + DOC_FILE))


def main(argv=None) -> int:
    import argparse
    p = argparse.ArgumentParser(prog="frmr-drift")
    p.add_argument("--catalog", default="catalog/FRMR.documentation.json")
    p.add_argument("--slices", default="slices")
    p.add_argument("--offline-doc", help="read the new FRMR from a local file instead of the network")
    p.add_argument("--summary-out", help="write the PR-body summary to this path")
    p.add_argument("--github-output", help="append changed=<bool> for GitHub Actions")
    p.add_argument("--apply", action="store_true", help="write the refreshed catalog and apply rename edits")
    args = p.parse_args(argv)

    new_doc = _load_doc(args.offline_doc)
    result = run(args.catalog, args.slices, new_doc)

    if args.apply and result["changed"]:
        Path(args.catalog).write_text(json.dumps(new_doc, indent=2, sort_keys=True))
        draft_mapping_edits(result["affected"], args.slices, apply=True)
    if args.summary_out:
        Path(args.summary_out).write_text(result["summary"])
    if args.github_output:
        with open(args.github_output, "a") as fh:
            fh.write(f"changed={'true' if result['changed'] else 'false'}\n")
    print(result["summary"])
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())


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
