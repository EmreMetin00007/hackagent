#!/usr/bin/env python3
"""
token-estimate.py — MCP tool şemalarının context token maliyetini tahmin eder.

Claude Code her istekte tüm kayıtlı MCP server'ların tool şemalarını (name +
description + JSON input schema) context'e yükler. Bu script o maliyeti server
ve profil bazında gösterir; profil seçiminin token tasarrufunu görünür kılar.

Kullanım:
    python3 scripts/token-estimate.py            # tüm server + profil tablosu
    python3 scripts/token-estimate.py --current  # ~/.claude.json'daki aktif profil

Tahmin: ~4 karakter ≈ 1 token (kaba ama tutarlı). Gerçek tokenizer'a göre ±%15.
"""
import os
import sys
import json
import asyncio
import importlib.util

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVERS_DIR = os.path.join(REPO, "mcp-servers")

ALL = ["kali-tools", "web-advanced", "ctf-platform", "ad-tools", "memory-server",
       "container-tools", "osint-tools", "telemetry", "browser", "rag-engine",
       "llm-security", "validator"]

PROFILES = {
    "min":   ["kali-tools", "memory-server", "telemetry"],
    "recon": ["kali-tools", "osint-tools", "browser", "memory-server", "telemetry"],
    "web":   ["kali-tools", "web-advanced", "validator", "llm-security", "browser", "memory-server", "rag-engine", "telemetry"],
    "llm":   ["llm-security", "browser", "web-advanced", "memory-server", "telemetry"],
    "ctf":   ["kali-tools", "ctf-platform", "validator", "memory-server", "rag-engine", "telemetry"],
    "ad":    ["kali-tools", "ad-tools", "container-tools", "memory-server", "telemetry"],
    "full":  ALL,
}


def schema_chars(server: str) -> tuple:
    """(tool_count, schema_char_count) — import edip list_tools'tan ölç."""
    path = os.path.join(SERVERS_DIR, f"mcp-{server}", "server.py")
    spec = importlib.util.spec_from_file_location(f"s_{server.replace('-', '_')}", path)
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
        tools = asyncio.run(mod.mcp.list_tools())
    except Exception as e:
        print(f"  ! {server} yüklenemedi: {e}", file=sys.stderr)
        return (0, 0)
    chars = 0
    for t in tools:
        chars += len(t.name) + len(t.description or "")
        try:
            chars += len(json.dumps(t.inputSchema))
        except Exception:
            pass
    return (len(tools), chars)


def main():
    measured = {s: schema_chars(s) for s in ALL}

    if "--current" in sys.argv:
        cj = os.path.join(os.path.expanduser("~"), ".claude.json")
        active = []
        if os.path.exists(cj):
            try:
                active = list(json.load(open(cj)).get("mcpServers", {}).keys())
            except Exception:
                pass
        chars = sum(measured.get(s, (0, 0))[1] for s in active if s in measured)
        tools = sum(measured.get(s, (0, 0))[0] for s in active if s in measured)
        print(f"Aktif profil: {len(active)} server, {tools} tool, ~{chars // 4} token/istek")
        print("Server'lar:", ", ".join(active) or "(yok)")
        return

    print(f"{'server':<18}{'tool':>5}{'~token':>9}")
    print("-" * 32)
    full_tok = 0
    for s in ALL:
        n, c = measured[s]
        full_tok += c // 4
        print(f"{s:<18}{n:>5}{c // 4:>9}")
    print("-" * 32)
    print(f"{'FULL (12 server)':<18}{sum(measured[s][0] for s in ALL):>5}{full_tok:>9}")
    print()
    print(f"{'PROFİL':<10}{'server':>7}{'tool':>6}{'~token':>9}{'tasarruf':>10}")
    print("-" * 42)
    for name, servers in PROFILES.items():
        tok = sum(measured[s][1] for s in servers) // 4
        tools = sum(measured[s][0] for s in servers)
        save = full_tok - tok
        pct = f"%{round(100 * save / full_tok)}" if full_tok else "-"
        print(f"{name:<10}{len(servers):>7}{tools:>6}{tok:>9}{pct:>10}")
    print()
    print("Profil değiştir:  bash scripts/cco-profile.sh <profil>")


if __name__ == "__main__":
    main()
