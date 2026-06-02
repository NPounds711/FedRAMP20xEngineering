import json
import shutil
import subprocess
import tempfile
from pathlib import Path


class OpaNotInstalled(RuntimeError):
    pass


def opa_available() -> bool:
    return shutil.which("opa") is not None


def evaluate(policy_dir, rego_package, input_data) -> dict:
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
        proc = subprocess.run(
            ["opa", "eval", "--format", "json", "-d", str(policy_dir), "-i", tf.name, query],
            capture_output=True, text=True, check=True,
        )
    finally:
        Path(tf.name).unlink(missing_ok=True)
    out = json.loads(proc.stdout)
    results = out.get("result", [])
    if not results:
        return {"result": "fail", "violations": ["policy produced no result document"]}
    value = results[0]["expressions"][0]["value"]
    return {
        "result": "pass" if value.get("pass") else "fail",
        "violations": list(value.get("violations", [])),
    }
