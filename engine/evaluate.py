import json
import shutil
import subprocess
import tempfile
from pathlib import Path


class OpaNotInstalled(RuntimeError):
    pass


class EvaluationError(RuntimeError):
    pass


def opa_available() -> bool:
    return shutil.which("opa") is not None


def evaluate(policy_dir, rego_package: str, input_data: dict) -> dict:
    if not opa_available():
        raise OpaNotInstalled(
            "opa binary not found on PATH; install from "
            "https://github.com/open-policy-agent/opa/releases"
        )
    query = f"data.{rego_package}.result"
    tf = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    try:
        json.dump(input_data, tf)
        tf.close()
        try:
            proc = subprocess.run(
                ["opa", "eval", "--format", "json", "-d", str(policy_dir), "-i", tf.name, query],
                capture_output=True, text=True, check=True,
            )
        except subprocess.CalledProcessError as exc:
            raise EvaluationError(
                f"opa eval failed (exit {exc.returncode}): {(exc.stderr or '').strip()}"
            ) from exc
    finally:
        Path(tf.name).unlink(missing_ok=True)
    try:
        out = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise EvaluationError(f"opa produced non-JSON output: {proc.stdout!r}") from exc
    results = out.get("result", [])
    if not results:
        return {"result": "fail", "violations": ["policy produced no result document"]}
    try:
        value = results[0]["expressions"][0]["value"]
    except (IndexError, KeyError) as exc:
        raise EvaluationError(f"unexpected opa result shape: {out!r}") from exc
    return {
        "result": "pass" if value.get("pass") else "fail",
        "violations": list(value.get("violations", [])),
    }
