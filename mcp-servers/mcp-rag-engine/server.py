#!/usr/bin/env python3
"""
MCP RAG Engine — CVE/Exploit/Writeup Knowledge Base.
ChromaDB tabanlı vector search ile semantic exploit bilgi tabanı.

Kullanım:
    python server.py
"""

import os
import json
import hashlib
import subprocess
from datetime import datetime
from mcp.server.fastmcp import FastMCP

try:
    import chromadb
    HAS_CHROMADB = True
except ImportError:
    HAS_CHROMADB = False

DB_DIR = os.path.join(os.environ.get("CCO_HOME", os.path.expanduser("~/.cco")), "rag_db")

mcp = FastMCP(
    "rag-engine",
    instructions="HackerAgent RAG — CVE, Exploit ve Writeup bilgi tabanında semantic search"
)

# ============================================================
# CHROMADB BAŞLATMA
# ============================================================

def _get_client():
    """ChromaDB persistent client oluştur."""
    if not HAS_CHROMADB:
        return None
    os.makedirs(DB_DIR, exist_ok=True)
    return chromadb.PersistentClient(path=DB_DIR)

def _get_collection(name: str):
    """Collection al veya oluştur."""
    client = _get_client()
    if not client:
        return None
    return client.get_or_create_collection(
        name=name,
        metadata={"hnsw:space": "cosine"}
    )

# ============================================================
# RAG ARAMA
# ============================================================

@mcp.tool()
def rag_search(
    query: str,
    collection: str = "all",
    top_k: int = 5
) -> str:
    """RAG bilgi tabanında semantic arama.
    Finding bulununca benzer geçmiş exploit'leri, CVE'leri ve writeup'ları getirir.

    Args:
        query: Arama sorgusu (ör: 'Apache Log4j RCE', 'SQL injection bypass WAF')
        collection: Aranacak koleksiyon ('exploits', 'writeups', 'cves', 'all')
        top_k: Döndürülecek sonuç sayısı
    """
    if not HAS_CHROMADB:
        return "HATA: ChromaDB kurulu değil. pip install chromadb"

    collections_to_search = []
    if collection == "all":
        collections_to_search = ["exploits", "writeups", "cves"]
    else:
        collections_to_search = [collection]

    all_results = []

    for coll_name in collections_to_search:
        coll = _get_collection(coll_name)
        if not coll or coll.count() == 0:
            continue

        try:
            results = coll.query(
                query_texts=[query],
                n_results=min(top_k, coll.count())
            )

            for i, doc_id in enumerate(results["ids"][0]):
                doc = results["documents"][0][i] if results["documents"] else ""
                meta = results["metadatas"][0][i] if results["metadatas"] else {}
                dist = results["distances"][0][i] if results["distances"] else 0

                all_results.append({
                    "collection": coll_name,
                    "id": doc_id,
                    "content": doc[:300] + "..." if len(doc) > 300 else doc,
                    "metadata": meta,
                    "relevance": round(1 - dist, 4) if dist else 0
                })
        except Exception as e:
            all_results.append({"collection": coll_name, "error": str(e)})

    if not all_results:
        return f"'{query}' için bilgi tabanında sonuç bulunamadı. Önce rag_ingest_* tool'larıyla veri yükleyin."

    # Relevance'a göre sırala
    all_results.sort(key=lambda x: x.get("relevance", 0), reverse=True)

    output = f"🔎 RAG Arama Sonuçları: '{query}'\n{'='*55}\n"
    for i, r in enumerate(all_results[:top_k], 1):
        if "error" in r:
            output += f"\n#{i} [{r['collection']}] HATA: {r['error']}\n"
            continue
        output += f"\n#{i} [{r['collection']}] (relevance: {r['relevance']:.2f})\n"
        if r.get("metadata"):
            meta = r["metadata"]
            if "title" in meta:
                output += f"  📌 {meta['title']}\n"
            if "severity" in meta:
                output += f"  ⚠️ Severity: {meta['severity']}\n"
            if "category" in meta:
                output += f"  📂 Category: {meta['category']}\n"
        output += f"  {r['content']}\n"

    return output


@mcp.tool()
def rag_similar_exploits(
    finding_description: str,
    top_k: int = 5
) -> str:
    """Bir finding/zafiyet açıklaması için en benzer geçmiş exploit'leri bul.
    Hermes 405B'yi daha az çağırarak hızlı sonuç verir.

    Args:
        finding_description: Bulunan zafiyetin açıklaması
        top_k: Döndürülecek sonuç sayısı
    """
    return rag_search(finding_description, collection="exploits", top_k=top_k)


# ============================================================
# VERİ YÜKLEME (INGEST)
# ============================================================

@mcp.tool()
def rag_ingest_exploitdb(
    search_query: str,
    max_results: int = 20
) -> str:
    """SearchSploit çıktısını parse edip RAG'a yükle.

    Args:
        search_query: SearchSploit arama sorgusu (ör: 'apache 2.4')
        max_results: Max sonuç sayısı
    """
    if not HAS_CHROMADB:
        return "HATA: ChromaDB kurulu değil."

    # SearchSploit çalıştır
    try:
        result = subprocess.run(
            f"searchsploit -j {search_query}",
            shell=True, capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            return f"SearchSploit hatası: {result.stderr}"

        data = json.loads(result.stdout)
        exploits = data.get("RESULTS_EXPLOIT", [])[:max_results]
    except json.JSONDecodeError:
        # JSON parse başarısız, text çıktıyı parse et
        lines = result.stdout.strip().split("\n")[2:]  # Header'ları atla
        exploits = []
        for line in lines[:max_results]:
            parts = line.split("|")
            if len(parts) >= 2:
                exploits.append({"Title": parts[0].strip(), "Path": parts[1].strip()})
    except Exception as e:
        return f"HATA: SearchSploit çalıştırılamadı: {e}"

    if not exploits:
        return f"'{search_query}' için exploit bulunamadı."

    coll = _get_collection("exploits")
    added = 0

    for exp in exploits:
        title = exp.get("Title", "Unknown")
        path = exp.get("Path", "")
        doc_id = hashlib.md5(f"{title}:{path}".encode()).hexdigest()[:16]

        content = f"Exploit: {title}\nPath: {path}"

        # Exploit içeriğini okumaya çalış
        if path and os.path.exists(f"/usr/share/exploitdb/{path}"):
            try:
                with open(f"/usr/share/exploitdb/{path}", "r", errors="replace") as f:
                    exploit_code = f.read()[:2000]
                content += f"\n\nCode:\n{exploit_code}"
            except Exception:
                pass

        try:
            coll.upsert(
                ids=[doc_id],
                documents=[content],
                metadatas=[{
                    "title": title,
                    "path": path,
                    "source": "exploitdb",
                    "category": "exploit",
                    "ingested_at": datetime.utcnow().isoformat()
                }]
            )
            added += 1
        except Exception:
            continue

    return f"✓ ExploitDB'den {added}/{len(exploits)} exploit RAG'a yüklendi. Koleksiyon: exploits ({coll.count()} toplam)"


@mcp.tool()
def rag_ingest_writeup(
    title: str,
    content: str,
    category: str = "general",
    tags: str = "",
    source: str = "manual"
) -> str:
    """CTF writeup veya HackerOne report'u RAG'a ekle.

    Args:
        title: Writeup başlığı
        content: Writeup içeriği (markdown/text)
        category: Kategori (web, pwn, reverse, crypto, forensics, misc)
        tags: Virgülle ayrılmış etiketler
        source: Kaynak (manual, ctftime, hackerone, bugcrowd)
    """
    if not HAS_CHROMADB:
        return "HATA: ChromaDB kurulu değil."

    coll = _get_collection("writeups")
    doc_id = hashlib.md5(f"{title}:{content[:100]}".encode()).hexdigest()[:16]

    try:
        coll.upsert(
            ids=[doc_id],
            documents=[f"{title}\n\n{content[:4000]}"],
            metadatas=[{
                "title": title,
                "category": category,
                "tags": tags,
                "source": source,
                "ingested_at": datetime.utcnow().isoformat()
            }]
        )
        return f"✓ Writeup RAG'a yüklendi: '{title}' [{category}] (ID: {doc_id})"
    except Exception as e:
        return f"HATA: Writeup yüklenemedi: {e}"


@mcp.tool()
def rag_ingest_cve(
    cve_id: str
) -> str:
    """CVE detaylarını NVD API'den çekip RAG'a yükle.

    Args:
        cve_id: CVE ID (ör: CVE-2024-1234, CVE-2021-44228)
    """
    if not HAS_CHROMADB:
        return "HATA: ChromaDB kurulu değil."

    import requests

    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        resp = requests.get(url, timeout=15, headers={"User-Agent": "HackerAgent/2.0"})
        resp.raise_for_status()
        data = resp.json()

        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return f"CVE bulunamadı: {cve_id}"

        cve_data = vulns[0].get("cve", {})
        descriptions = cve_data.get("descriptions", [])
        desc = next((d["value"] for d in descriptions if d["lang"] == "en"), "No description")

        # CVSS score
        metrics = cve_data.get("metrics", {})
        cvss_score = "N/A"
        severity = "unknown"
        for metric_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if metric_key in metrics:
                cvss_data = metrics[metric_key][0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore", "N/A")
                severity = cvss_data.get("baseSeverity", "unknown").lower()
                break

        # References
        refs = cve_data.get("references", [])
        ref_urls = [r["url"] for r in refs[:5]]

        content = f"""CVE: {cve_id}
CVSS Score: {cvss_score} ({severity})
Description: {desc}
References: {', '.join(ref_urls)}"""

        coll = _get_collection("cves")
        coll.upsert(
            ids=[cve_id],
            documents=[content],
            metadatas=[{
                "title": cve_id,
                "cvss_score": str(cvss_score),
                "severity": severity,
                "source": "nvd",
                "category": "cve",
                "ingested_at": datetime.utcnow().isoformat()
            }]
        )

        return f"✓ {cve_id} RAG'a yüklendi (CVSS: {cvss_score}, {severity})"
    except Exception as e:
        return f"HATA: CVE çekilemedi: {e}"


@mcp.tool()
def rag_bulk_ingest(
    source: str = "payloads",
    path: str = ""
) -> str:
    """Toplu veri yükleme — PayloadsAllTheThings, HackTricks vb. kaynaklardan.

    Args:
        source: Kaynak tipi:
            - 'payloads': PayloadsAllTheThings (git clone gerekli)
            - 'hacktricks': HackTricks (git clone gerekli)
            - 'directory': Belirtilen dizindeki tüm .md/.txt dosyaları
        path: Kaynak dizin yolu (boş: varsayılan konum)
    """
    if not HAS_CHROMADB:
        return "HATA: ChromaDB kurulu değil."

    source_paths = {
        "payloads": path or "/opt/PayloadsAllTheThings",
        "hacktricks": path or "/opt/HackTricks",
        "directory": path
    }

    src_dir = source_paths.get(source, path)
    if not src_dir or not os.path.isdir(src_dir):
        return f"HATA: Dizin bulunamadı: {src_dir}. Önce git clone yapın."

    coll = _get_collection("writeups")
    added = 0
    errors = 0

    for root, _, files in os.walk(src_dir):
        for fname in files:
            if not fname.endswith((".md", ".txt")):
                continue

            fpath = os.path.join(root, fname)
            try:
                with open(fpath, "r", errors="replace") as f:
                    content = f.read()

                if len(content) < 50:
                    continue

                # Büyük dosyaları chunk'la
                chunks = [content[i:i+3000] for i in range(0, min(len(content), 15000), 3000)]

                for ci, chunk in enumerate(chunks):
                    doc_id = hashlib.md5(f"{fpath}:{ci}".encode()).hexdigest()[:16]
                    rel_path = os.path.relpath(fpath, src_dir)

                    coll.upsert(
                        ids=[doc_id],
                        documents=[f"Source: {rel_path}\n\n{chunk}"],
                        metadatas=[{
                            "title": fname,
                            "source": source,
                            "file_path": rel_path,
                            "chunk_index": ci,
                            "category": _guess_category(rel_path),
                            "ingested_at": datetime.utcnow().isoformat()
                        }]
                    )
                    added += 1
            except Exception:
                errors += 1

    return f"✓ Bulk ingest tamamlandı: {added} chunk yüklendi ({errors} hata). Koleksiyon: writeups ({coll.count()} toplam)"


@mcp.tool()
def rag_stats() -> str:
    """RAG bilgi tabanı istatistikleri."""
    if not HAS_CHROMADB:
        return "HATA: ChromaDB kurulu değil."

    output = "📚 RAG Bilgi Tabanı İstatistikleri\n" + "=" * 40 + "\n"

    for name in ["exploits", "writeups", "cves"]:
        coll = _get_collection(name)
        count = coll.count() if coll else 0
        emoji = {"exploits": "💥", "writeups": "📝", "cves": "🐛"}.get(name, "📄")
        output += f"{emoji} {name}: {count} kayıt\n"

    output += f"\n📁 DB yolu: {DB_DIR}"
    return output


# ============================================================
# YARDIMCI
# ============================================================

def _guess_category(file_path: str) -> str:
    """Dosya yolundan kategori tahmin et."""
    path_lower = file_path.lower()
    categories = {
        "sql": "web", "xss": "web", "ssrf": "web", "csrf": "web", "xxe": "web",
        "injection": "web", "traversal": "web", "upload": "web", "ssti": "web",
        "buffer": "pwn", "overflow": "pwn", "format": "pwn", "rop": "pwn", "heap": "pwn",
        "reverse": "reverse", "assembly": "reverse", "ghidra": "reverse",
        "crypto": "crypto", "rsa": "crypto", "aes": "crypto", "hash": "crypto",
        "forensic": "forensics", "memory": "forensics", "pcap": "forensics", "steg": "forensics",
        "linux": "privesc", "windows": "privesc", "privilege": "privesc",
        "active-directory": "ad", "kerberos": "ad", "ldap": "ad",
    }
    for keyword, cat in categories.items():
        if keyword in path_lower:
            return cat
    return "misc"


# ============================================================
# SERVER BAŞLAT
# ============================================================

if __name__ == "__main__":
    mcp.run(transport="stdio")
