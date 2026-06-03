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
