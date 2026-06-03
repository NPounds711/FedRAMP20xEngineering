from pathlib import Path

from tools.sync import BASELINE_FILES, sync_baselines


def test_sync_baselines_offline(tmp_path):
    offline = tmp_path / "src"
    offline.mkdir()
    name = BASELINE_FILES[0]
    (offline / name).write_text('{"profile": {}}')
    dest = tmp_path / "catalog" / "baselines"

    result = sync_baselines(str(dest), offline_dir=str(offline))

    assert name in result["written"]
    assert (dest / name).exists()
    # files absent from offline_dir are skipped, not failed
    assert result["failed"] == {}
