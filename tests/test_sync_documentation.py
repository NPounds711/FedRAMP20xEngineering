from tools.sync import DOC_FILE, sync_documentation


def test_sync_documentation_offline(tmp_path):
    offline = tmp_path / "src"
    offline.mkdir()
    (offline / DOC_FILE).write_text('{"KSI": {}}')
    dest = tmp_path / "catalog"

    result = sync_documentation(str(dest), offline_dir=str(offline))

    assert DOC_FILE in result["written"]
    assert (dest / DOC_FILE).exists()
    assert result["failed"] == {}


def test_sync_documentation_records_fetch_failure(tmp_path, monkeypatch):
    import tools.sync as sync
    import urllib.error

    def boom(url):
        raise urllib.error.URLError("source moved")

    monkeypatch.setattr(sync, "_fetch", boom)
    result = sync.sync_documentation(str(tmp_path / "catalog"))  # online mode -> calls _fetch
    assert result["written"] == {}
    assert DOC_FILE in result["failed"]
    assert "source moved" in result["failed"][DOC_FILE]


def test_sync_documentation_offline_absent_is_skipped(tmp_path):
    # offline dir with no FRMR file -> skipped cleanly, nothing written or failed
    offline = tmp_path / "empty"
    offline.mkdir()
    result = sync_documentation(str(tmp_path / "catalog"), offline_dir=str(offline))
    assert result == {"written": {}, "failed": {}}
