"""
mcp-validator deterministik doğrulama — offline birim testleri.
Network gerektiren validator tool'ları test edilmez; saf oracle/yardımcı
fonksiyonlar, dispatcher routing ve rapor üretimi doğrulanır.
"""
import json
import pytest

from conftest import load_server, list_tool_names


def _v():
    return load_server("validator")


def test_validator_imports_and_tool_count():
    mod = _v()
    assert hasattr(mod, "mcp")
    names = list_tool_names(mod)
    assert len(names) == 13, f"validator 13 tool sunmalı, {len(names)} bulundu"


def test_ssti_arithmetic_oracle():
    mod = _v()
    # render edilmiş: sonuç var, ifade yok → True
    assert mod._ssti_oracle("Hello 49 world", 7, 7) is True
    # render edilmemiş: ifade aynen yansımış → False
    assert mod._ssti_oracle("Hello {{7*7}} -> 7*7", 7, 7) is False
    # sonuç hiç yok → False
    assert mod._ssti_oracle("nothing here", 7, 7) is False


def test_boolean_differential_oracle():
    mod = _v()
    base = {"ok": True, "status": 200, "len": 1000, "text": "A" * 1000}
    true_r = {"ok": True, "status": 200, "len": 1000, "text": "A" * 1000}
    false_r = {"ok": True, "status": 200, "len": 50, "text": "B" * 50}
    assert mod._boolean_confirms(base, true_r, false_r) is True
    # TRUE/FALSE aynıysa (fark yok) → onaylanmaz
    assert mod._boolean_confirms(base, true_r, true_r) is False


def test_file_signatures():
    mod = _v()
    assert mod.LINUX_FILE_SIG.search("root:x:0:0:root:/root:/bin/bash")
    assert mod.WIN_FILE_SIG.search("[fonts]\nrandom=1")
    assert not mod.LINUX_FILE_SIG.search("just a normal page")


def test_dispatcher_unknown_type():
    mod = _v()
    out = json.loads(mod.validate_finding("totally-unknown-vuln", "http://x/"))
    assert out["verdict"] == "ERROR"
    assert "supported" in out


def test_report_generation_confirmed():
    mod = _v()
    result = json.dumps({
        "vuln_type": "SQL Injection (boolean-based)",
        "target": "http://t/item?id=1",
        "verdict": "CONFIRMED",
        "confidence": 0.9,
        "severity": "high",
        "oracle": "differential_boolean",
        "evidence": {"true_payload": "1 AND 1=1"},
        "reproduction": ["curl -sk 'http://t/item?id=1 AND 1=1'"],
        "false_positive_guard": "deterministik",
        "notes": "ok",
        "timestamp": "2026-06-14T00:00:00Z",
    })
    md = mod.generate_validation_report(result)
    assert "# ✅ Doğrulama Raporu" in md
    assert "Reproduction" in md
    assert "Remediation" in md
    assert "prepared statement" in md.lower()


def test_confidence_zero_when_unconfirmed():
    mod = _v()
    out = json.loads(mod._result("XSS", "http://t/", mod.UNCONFIRMED,
                                 "unescaped_reflection", {}, "-"))
    assert out["confidence"] == 0.0
    assert out["severity"] == "info"
