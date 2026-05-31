"""
CCO pytest konfigürasyonu — testler izole bir CCO_HOME kullanır,
gerçek ~/.cco verisine dokunmaz. Tüm testler OFFLINE çalışır (network yok).
"""
import os
import sys
import tempfile
import importlib.util

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVERS_DIR = os.path.join(REPO_ROOT, "mcp-servers")


@pytest.fixture(scope="session", autouse=True)
def isolated_cco_home():
    """Testler boyunca geçici CCO_HOME ayarla (gerçek veriyi koru)."""
    tmp = tempfile.mkdtemp(prefix="cco_pytest_")
    old = os.environ.get("CCO_HOME")
    os.environ["CCO_HOME"] = tmp
    yield tmp
    if old is not None:
        os.environ["CCO_HOME"] = old
    else:
        os.environ.pop("CCO_HOME", None)


def load_server(name: str):
    """mcp-<name>/server.py modülünü izole şekilde yükle, modülü döndür."""
    path = os.path.join(SERVERS_DIR, f"mcp-{name}", "server.py")
    spec = importlib.util.spec_from_file_location(f"cco_{name.replace('-', '_')}", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def list_tool_names(mod):
    import asyncio
    return [t.name for t in asyncio.run(mod.mcp.list_tools())]
