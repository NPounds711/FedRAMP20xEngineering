import argparse
import json
import sys
from pathlib import Path

from jsonschema import ValidationError

from engine import align as align_mod
from engine import collect as collect_mod
from engine import evaluate as eval_mod
from engine import report as report_mod
from engine.evaluate import EvaluationError, OpaNotInstalled
from engine.evidence import record_evidence, verify_chain
from engine.render import human as render_human
from engine.render import json as render_json
from engine.render import oscal as render_oscal
from engine.render import yaml as render_yaml
from engine.slice import load_mapping

_RENDERERS = {
    "json": render_json,
    "yaml": render_yaml,
    "oscal": render_oscal,
    "human": render_human,
}

_USER_ERRORS = (
    FileNotFoundError,
    FileExistsError,
    json.JSONDecodeError,
    ValidationError,
    OpaNotInstalled,
    EvaluationError,
)


def _run_slice(slice_dir, provider, evidence_dir, run_id, config=None):
    mapping = load_mapping(slice_dir)
    payload = collect_mod.collect(slice_dir, provider, config or {})
    record = record_evidence(mapping["capability"], provider, run_id, payload, evidence_dir)
    result = eval_mod.evaluate(Path(slice_dir) / "policy", mapping["rego_package"], payload)
    return align_mod.align(mapping, result, record)


def _load_determinations(path):
    data = json.loads(Path(path).read_text())
    return data if isinstance(data, list) else [data]


def _build_parser():
    parser = argparse.ArgumentParser(prog="fr20x")
    sub = parser.add_subparsers(dest="cmd", required=True)

    rs = sub.add_parser("run-slice", help="collect -> record -> evaluate -> align for one slice/provider")
    rs.add_argument("slice_dir")
    rs.add_argument("--provider", required=True)
    rs.add_argument("--run-id", required=True)
    rs.add_argument("--evidence-dir", default="evidence")
    rs.add_argument("--config", default=None, help="path to a JSON file passed to the collector")

    rn = sub.add_parser("render", help="render determinations to a target format")
    rn.add_argument("determinations_json")
    rn.add_argument("--format", choices=list(_RENDERERS), required=True)

    rp = sub.add_parser("report", help="coverage + required/recommended rollup")
    rp.add_argument("ksi_index_csv")
    rp.add_argument("determinations_json")

    sy = sub.add_parser("sync", help="sync FRMR catalog from FedRAMP/docs")
    sy.add_argument("--dest", default="catalog/frmr")
    sy.add_argument("--offline-dir")
    sy.add_argument("--baselines", action="store_true",
                    help="also sync Rev 5 OSCAL baseline profiles into catalog/baselines")
    sy.add_argument("--baselines-dest", default="catalog/baselines")

    vc = sub.add_parser("verify", help="verify a capability's evidence chain")
    vc.add_argument("capability")
    vc.add_argument("--evidence-dir", default="evidence")
    return parser


def _dispatch(args) -> int:
    if args.cmd == "run-slice":
        config = json.loads(Path(args.config).read_text()) if args.config else None
        det = _run_slice(args.slice_dir, args.provider, args.evidence_dir, args.run_id, config)
        print(json.dumps(det, indent=2, sort_keys=True))
        return 0
    if args.cmd == "render":
        dets = _load_determinations(args.determinations_json)
        print(_RENDERERS[args.format].render(dets))
        return 0
    if args.cmd == "report":
        idx = report_mod.load_ksi_index(args.ksi_index_csv)
        dets = _load_determinations(args.determinations_json)
        print(json.dumps(report_mod.coverage(idx, dets), indent=2))
        return 0
    if args.cmd == "sync":
        from tools.sync import sync as do_sync
        out = {"frmr": do_sync(args.dest, args.offline_dir)}
        if args.baselines:
            from tools.sync import sync_baselines
            out["baselines"] = sync_baselines(args.baselines_dest, args.offline_dir)
        print(json.dumps(out, indent=2))
        return 0
    if args.cmd == "verify":
        chain = Path(args.evidence_dir) / args.capability / "chain.jsonl"
        if not chain.exists():
            print(
                f"fr20x: error: no evidence chain for capability "
                f"'{args.capability}' under {args.evidence_dir}",
                file=sys.stderr,
            )
            return 2
        ok = verify_chain(args.capability, args.evidence_dir)
        print("OK" if ok else "TAMPERED")
        return 0 if ok else 1
    return 2


def main(argv=None):
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        return _dispatch(args)
    except _USER_ERRORS as exc:
        print(f"fr20x: error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
