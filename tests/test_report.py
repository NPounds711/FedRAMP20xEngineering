from pathlib import Path

from engine.report import coverage, load_ksi_index

FIX = Path(__file__).resolve().parent / "fixtures" / "ksi_index.csv"


def _det(ksi, obligation, result):
    return {
        "capability": ksi.lower(), "result": result, "evidence_ref": "b" * 64,
        "collected_at": "2026-06-02T00:00:00Z",
        "frameworks": {"fedramp-20x": [{"ksi": ksi, "obligation": obligation}],
                       "nist-800-53-rev5": []},
    }


def test_load_ksi_index_reads_obligation():
    idx = load_ksi_index(FIX)
    assert {"ksi": "KSI-A", "obligation": "required"} in idx


def test_coverage_math_and_gap_ordering():
    idx = load_ksi_index(FIX)  # KSI-A required, KSI-B required, KSI-C recommended, KSI-D recommended
    dets = [_det("KSI-A", "required", "pass"), _det("KSI-C", "recommended", "pass")]
    cov = coverage(idx, dets)
    assert cov["total_ksis"] == 4
    assert cov["automated_pct"] == 50.0
    assert cov["meets_70_threshold"] is False
    assert cov["required_addressed"] == "1/2"
    assert cov["recommended_addressed"] == "1/2"
    assert cov["gaps"][0]["obligation"] == "required"
    assert cov["gaps"][0]["ksi"] == "KSI-B"
