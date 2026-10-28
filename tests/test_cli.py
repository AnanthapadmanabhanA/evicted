import json

from evicted import cli


def test_cli_vulnerable_exit_code_and_output(capsys):
    rc = cli.main(["scan", "--target", "mock-vulnerable"])
    out = capsys.readouterr().out
    assert rc == 1                      # vulnerabilities present -> non-zero
    assert "6 vulnerable" in out
    assert "EV-REVOKE-PERSIST" in out


def test_cli_hardened_exit_code(capsys):
    rc = cli.main(["scan", "--target", "mock-hardened"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "0 vulnerable" in out


def test_cli_json_output(tmp_path, capsys):
    out = tmp_path / "r.json"
    cli.main(["scan", "--target", "mock-vulnerable", "--json", str(out), "--quiet"])
    assert capsys.readouterr().out == ""
    data = json.loads(out.read_text())
    assert data["tool"] == "evicted"
    assert data["summary"]["vulnerable"] == 6
    assert data["summary"]["worst_severity"] == "critical"
    # worst-first ordering: the first finding is a vulnerable critical
    assert data["findings"][0]["status"] == "vulnerable"
    assert data["findings"][0]["severity"] == "critical"
