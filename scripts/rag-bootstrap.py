#!/usr/bin/env python3
"""
CCO RAG Bootstrap — NVD CVE feed + ExploitDB + PayloadsAllTheThings ile
ChromaDB bilgi tabanını ilk kez doldurur.

Kullanım:
    python3 scripts/rag-bootstrap.py                 # tam bootstrap
    python3 scripts/rag-bootstrap.py --dry-run        # bağlantı testi
    python3 scripts/rag-bootstrap.py --cve-only       # sadece CVE'ler
    python3 scripts/rag-bootstrap.py --payloads-only  # sadece PayloadsAllTheThings
    python3 scripts/rag-bootstrap.py --cve-count 200  # 200 CVE çek
"""

import os
import sys
import json
import time
import hashlib
import argparse
import subprocess
from datetime import datetime, timezone

try:
    import requests
except ImportError:
    print("HATA: requests kurulu değil — pip install requests")
    sys.exit(1)

try:
    import chromadb
except ImportError:
    print("HATA: chromadb kurulu değil — pip install chromadb")
    sys.exit(1)

# ──────────────────────────────────────────────────────────────
# Konfigürasyon
# ──────────────────────────────────────────────────────────────
CCO_HOME = os.environ.get("CCO_HOME", os.path.expanduser("~/.cco"))
DB_DIR   = os.path.join(CCO_HOME, "rag_db")
NVD_API  = "https://services.nvd.nist.gov/rest/json/cves/2.0"
HEADERS  = {"User-Agent": "HackerAgent-Bootstrap/1.0"}

PAYLOADS_REPO = "https://github.com/swisskyrepo/PayloadsAllTheThings.git"
PAYLOADS_DIR  = "/opt/PayloadsAllTheThings"

# ──────────────────────────────────────────────────────────────
# ChromaDB yardımcıları
# ──────────────────────────────────────────────────────────────

def get_collection(name: str):
    os.makedirs(DB_DIR, exist_ok=True)
    client = chromadb.PersistentClient(path=DB_DIR)
    return client.get_or_create_collection(
        name=name,
        metadata={"hnsw:space": "cosine"}
    )


def upsert_batch(collection, ids, documents, metadatas, batch_size=100):
    """ChromaDB'ye batch upsert — büyük listeler için chunk'lar."""
    total = 0
    for i in range(0, len(ids), batch_size):
        collection.upsert(
            ids=ids[i:i+batch_size],
            documents=documents[i:i+batch_size],
            metadatas=metadatas[i:i+batch_size]
        )
        total += len(ids[i:i+batch_size])
    return total


# ──────────────────────────────────────────────────────────────
# Modül 1: NVD CVE Feed
# ──────────────────────────────────────────────────────────────

def fetch_nvd_cves(count: int = 100, dry_run: bool = False) -> int:
    """NVD API'den HIGH/CRITICAL CVE'leri çek ve RAG'a yükle."""
    print(f"\n[NVD] Son {count} HIGH/CRITICAL CVE çekiliyor...")

    if dry_run:
        try:
            r = requests.get(NVD_API, params={"resultsPerPage": 1}, headers=HEADERS, timeout=10)
            r.raise_for_status()
            total = r.json().get("totalResults", "?")
            print(f"  ✓ NVD API erişilebilir — toplam {total} CVE mevcut")
            return 0
        except Exception as e:
            print(f"  ✗ NVD API bağlantı hatası: {e}")
            return -1

    coll = get_collection("cves")
    added = 0
    errors = 0
    page_size = 100
    start_index = 0

    # Severity filtresi: HIGH + CRITICAL ayrı ayrı çek
    for severity in ["HIGH", "CRITICAL"]:
        remaining = count // 2
        start_index = 0

        while remaining > 0:
            fetch_count = min(page_size, remaining)
            params = {
                "resultsPerPage": fetch_count,
                "startIndex": start_index,
                "cvssV3Severity": severity
            }

            try:
                resp = requests.get(NVD_API, params=params, headers=HEADERS, timeout=30)
                resp.raise_for_status()
                data = resp.json()
            except Exception as e:
                print(f"  ✗ NVD API hatası ({severity}): {e}")
                break

            vulns = data.get("vulnerabilities", [])
            if not vulns:
                break

            ids_batch, docs_batch, meta_batch = [], [], []

            for vuln in vulns:
                cve_data = vuln.get("cve", {})
                cve_id = cve_data.get("id", "UNKNOWN")

                # Description
                descs = cve_data.get("descriptions", [])
                desc = next((d["value"] for d in descs if d["lang"] == "en"), "No description")

                # CVSS
                metrics = cve_data.get("metrics", {})
                cvss_score = "N/A"
                cvss_severity = severity.lower()
                for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    if key in metrics:
                        cvss_data = metrics[key][0].get("cvssData", {})
                        cvss_score = cvss_data.get("baseScore", "N/A")
                        cvss_severity = cvss_data.get("baseSeverity", severity).lower()
                        break

                # Published date
                published = cve_data.get("published", "")[:10]

                # CWE
                weaknesses = cve_data.get("weaknesses", [])
                cwes = []
                for w in weaknesses:
                    for d in w.get("description", []):
                        if d.get("lang") == "en":
                            cwes.append(d["value"])

                # References (top 3)
                refs = [r["url"] for r in cve_data.get("references", [])[:3]]

                doc_text = (
                    f"CVE: {cve_id}\n"
                    f"Severity: {cvss_severity.upper()} (CVSS: {cvss_score})\n"
                    f"Published: {published}\n"
                    f"CWE: {', '.join(cwes) or 'N/A'}\n"
                    f"Description: {desc[:1000]}\n"
                    f"References: {', '.join(refs)}"
                )

                ids_batch.append(cve_id)
                docs_batch.append(doc_text)
                meta_batch.append({
                    "title": cve_id,
                    "cvss_score": str(cvss_score),
                    "severity": cvss_severity,
                    "published": published,
                    "cwe": ", ".join(cwes) or "N/A",
                    "source": "nvd",
                    "category": "cve",
                    "ingested_at": datetime.now(timezone.utc).isoformat()
                })

            if ids_batch:
                try:
                    upsert_batch(coll, ids_batch, docs_batch, meta_batch)
                    added += len(ids_batch)
                    print(f"  ✓ {severity}: {added} CVE yüklendi...", end="\r")
                except Exception as e:
                    errors += len(ids_batch)
                    print(f"  ✗ Batch upsert hatası: {e}")

            remaining -= len(vulns)
            start_index += len(vulns)

            if len(vulns) < fetch_count:
                break

            # NVD rate limit: 5 req/30s (API key olmadan)
            time.sleep(6)

    total_cves = coll.count()
    print(f"\n  ✓ NVD tamamlandı: {added} CVE eklendi, {errors} hata. DB toplam: {total_cves}")
    return added


# ──────────────────────────────────────────────────────────────
# Modül 2: PayloadsAllTheThings
# ──────────────────────────────────────────────────────────────

def _guess_category(path: str) -> str:
    """Dosya yolundan güvenlik kategorisi tahmin et."""
    p = path.lower()
    mapping = {
        "sql": "web", "xss": "web", "ssrf": "web", "csrf": "web", "xxe": "web",
        "ssti": "web", "traversal": "web", "upload": "web", "injection": "web",
        "lfi": "web", "rfi": "web", "idor": "web", "cors": "web", "deserializ": "web",
        "buffer": "pwn", "overflow": "pwn", "format": "pwn", "rop": "pwn", "heap": "pwn",
        "reverse": "reverse", "assembly": "reverse", "ghidra": "reverse",
        "crypto": "crypto", "rsa": "crypto", "aes": "crypto", "hash": "crypto",
        "forensic": "forensics", "memory": "forensics", "pcap": "forensics",
        "steg": "forensics", "volatility": "forensics",
        "linux": "privesc", "windows": "privesc", "privilege": "privesc",
        "active_directory": "ad", "active-directory": "ad", "kerberos": "ad",
        "ldap": "ad", "ad_": "ad", "_ad": "ad",
        "cloud": "cloud", "aws": "cloud", "gcp": "cloud", "azure": "cloud",
        "docker": "container", "kubernetes": "container", "k8s": "container",
        "android": "mobile", "ios": "mobile", "apk": "mobile", "frida": "mobile",
    }
    for keyword, cat in mapping.items():
        if keyword in p:
            return cat
    return "misc"


def ingest_payloads_allthethings(dry_run: bool = False) -> int:
    """PayloadsAllTheThings'i clone edip RAG'a yükle."""
    print(f"\n[PAYLOADS] PayloadsAllTheThings ingest ediliyor...")

    if dry_run:
        if os.path.isdir(PAYLOADS_DIR):
            print(f"  ✓ {PAYLOADS_DIR} mevcut — ingest hazır")
        else:
            print(f"  ℹ {PAYLOADS_DIR} yok — bootstrap sırasında clone edilecek")
        return 0

    # Clone if not present
    if not os.path.isdir(PAYLOADS_DIR):
        print(f"  📥 {PAYLOADS_REPO} clone ediliyor...")
        try:
            result = subprocess.run(
                ["git", "clone", "--depth=1", PAYLOADS_REPO, PAYLOADS_DIR],
                capture_output=True, text=True, timeout=120
            )
            if result.returncode != 0:
                print(f"  ✗ Clone hatası: {result.stderr[:200]}")
                print("  ℹ Alternatif: manuel olarak git clone edip tekrar çalıştırın")
                return -1
            print(f"  ✓ Clone tamamlandı: {PAYLOADS_DIR}")
        except FileNotFoundError:
            print("  ✗ git bulunamadı — apt install git")
            return -1
        except subprocess.TimeoutExpired:
            print("  ✗ Clone zaman aşımı (120s)")
            return -1

    coll = get_collection("writeups")
    added = 0
    errors = 0

    for root, dirs, files in os.walk(PAYLOADS_DIR):
        # Hidden dirs ve .git atla
        dirs[:] = [d for d in dirs if not d.startswith(".")]

        for fname in files:
            if not fname.endswith((".md", ".txt")):
                continue

            fpath = os.path.join(root, fname)
            rel_path = os.path.relpath(fpath, PAYLOADS_DIR)

            try:
                with open(fpath, "r", errors="replace") as f:
                    content = f.read()

                if len(content.strip()) < 50:
                    continue

                # 3KB chunk'lar halinde yükle (max 15KB / dosya)
                max_bytes = 15000
                chunk_size = 3000
                chunks = [
                    content[i:i+chunk_size]
                    for i in range(0, min(len(content), max_bytes), chunk_size)
                ]

                ids_batch, docs_batch, meta_batch = [], [], []
                for ci, chunk in enumerate(chunks):
                    doc_id = hashlib.md5(f"{rel_path}:{ci}".encode()).hexdigest()[:16]
                    ids_batch.append(doc_id)
                    docs_batch.append(f"Source: {rel_path}\n\n{chunk}")
                    meta_batch.append({
                        "title": fname.replace(".md", "").replace(".txt", ""),
                        "source": "payloads_allthethings",
                        "file_path": rel_path,
                        "chunk_index": ci,
                        "category": _guess_category(rel_path),
                        "ingested_at": datetime.now(timezone.utc).isoformat()
                    })

                upsert_batch(coll, ids_batch, docs_batch, meta_batch)
                added += len(chunks)

            except Exception as e:
                errors += 1

        if added > 0 and added % 500 == 0:
            print(f"  ✓ {added} chunk yüklendi...", end="\r")

    print(f"\n  ✓ PayloadsAllTheThings tamamlandı: {added} chunk yüklendi, {errors} hata")
    return added


# ──────────────────────────────────────────────────────────────
# Modül 3: Temel CVE Seti (offline, her zaman çalışır)
# ──────────────────────────────────────────────────────────────

SEED_CVES = [
    # Web
    "CVE-2021-44228",  # Log4Shell
    "CVE-2022-22965",  # Spring4Shell
    "CVE-2023-44487",  # HTTP/2 Rapid Reset
    "CVE-2021-34527",  # PrintNightmare
    "CVE-2020-1472",   # Zerologon
    "CVE-2019-19781",  # Citrix RCE
    "CVE-2021-26855",  # ProxyLogon Exchange
    "CVE-2021-21985",  # VMware vCenter RCE
    "CVE-2022-1388",   # F5 BIG-IP RCE
    "CVE-2023-23397",  # Outlook NTLM
    "CVE-2023-20198",  # Cisco IOS XE
    "CVE-2024-3400",   # PAN-OS RCE
    "CVE-2024-21413",  # Outlook MonikerLink
    "CVE-2024-6387",   # OpenSSH regreSSHion
    "CVE-2024-4577",   # PHP RCE (Windows CGI)
]


def ingest_seed_cves(dry_run: bool = False) -> int:
    """Temel CVE listesini NVD'den çekip RAG'a yükle."""
    print(f"\n[SEED] {len(SEED_CVES)} kritik CVE seed'i yükleniyor...")

    if dry_run:
        print(f"  ✓ {len(SEED_CVES)} CVE seed listesi hazır")
        return 0

    coll = get_collection("cves")
    added = 0

    for cve_id in SEED_CVES:
        try:
            resp = requests.get(
                NVD_API,
                params={"cveId": cve_id},
                headers=HEADERS,
                timeout=15
            )
            resp.raise_for_status()
            data = resp.json()
            vulns = data.get("vulnerabilities", [])

            if not vulns:
                print(f"  ✗ {cve_id}: bulunamadı")
                continue

            cve_data = vulns[0].get("cve", {})
            descs = cve_data.get("descriptions", [])
            desc = next((d["value"] for d in descs if d["lang"] == "en"), "No description")

            metrics = cve_data.get("metrics", {})
            cvss_score = "N/A"
            severity = "critical"
            for key in ["cvssMetricV31", "cvssMetricV30"]:
                if key in metrics:
                    cvss_data = metrics[key][0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore", "N/A")
                    severity = cvss_data.get("baseSeverity", "CRITICAL").lower()
                    break

            doc_text = (
                f"CVE: {cve_id}\n"
                f"Severity: {severity.upper()} (CVSS: {cvss_score})\n"
                f"Description: {desc[:1500]}"
            )

            coll.upsert(
                ids=[cve_id],
                documents=[doc_text],
                metadatas=[{
                    "title": cve_id,
                    "cvss_score": str(cvss_score),
                    "severity": severity,
                    "source": "nvd_seed",
                    "category": "cve",
                    "ingested_at": datetime.now(timezone.utc).isoformat()
                }]
            )
            added += 1
            print(f"  ✓ {cve_id} (CVSS: {cvss_score})")
            time.sleep(6)  # NVD rate limit

        except Exception as e:
            print(f"  ✗ {cve_id}: {e}")
            time.sleep(2)

    print(f"\n  ✓ Seed CVE tamamlandı: {added}/{len(SEED_CVES)} yüklendi")
    return added


# ──────────────────────────────────────────────────────────────
# Ana Fonksiyon
# ──────────────────────────────────────────────────────────────

def print_stats():
    """Mevcut RAG istatistiklerini göster."""
    print("\n📚 RAG Bilgi Tabanı Durumu:")
    print("=" * 40)
    for name in ["exploits", "writeups", "cves"]:
        try:
            coll = get_collection(name)
            count = coll.count()
            emoji = {"exploits": "💥", "writeups": "📝", "cves": "🐛"}.get(name, "📄")
            print(f"  {emoji} {name:12s}: {count:,} kayıt")
        except Exception as e:
            print(f"  ✗ {name}: {e}")
    print(f"\n  📁 DB yolu: {DB_DIR}")


def main():
    parser = argparse.ArgumentParser(
        description="CCO RAG Bootstrap — Güvenlik bilgi tabanını doldur"
    )
    parser.add_argument("--dry-run", action="store_true",
                        help="Bağlantıları test et, veri yazma")
    parser.add_argument("--cve-only", action="store_true",
                        help="Sadece CVE'leri yükle")
    parser.add_argument("--payloads-only", action="store_true",
                        help="Sadece PayloadsAllTheThings yükle")
    parser.add_argument("--seed-only", action="store_true",
                        help="Sadece seed CVE listesini yükle (hızlı, 15 CVE)")
    parser.add_argument("--cve-count", type=int, default=100,
                        help="Yüklenecek CVE sayısı (varsayılan: 100)")
    parser.add_argument("--stats", action="store_true",
                        help="Mevcut DB istatistiklerini göster ve çık")

    args = parser.parse_args()

    print("╔══════════════════════════════════════╗")
    print("║   CCO RAG Bootstrap v1.0             ║")
    print("║   Güvenlik bilgi tabanı kurulum       ║")
    print("╚══════════════════════════════════════╝")
    print(f"  DB yolu: {DB_DIR}")
    print(f"  Mod: {'DRY-RUN' if args.dry_run else 'FULL BOOTSTRAP'}")

    if args.stats:
        print_stats()
        return

    start_time = time.time()
    total_added = 0

    if args.seed_only:
        total_added += ingest_seed_cves(args.dry_run)
    elif args.cve_only:
        total_added += ingest_seed_cves(args.dry_run)
        total_added += fetch_nvd_cves(args.cve_count, args.dry_run)
    elif args.payloads_only:
        total_added += ingest_payloads_allthethings(args.dry_run)
    else:
        # Tam bootstrap
        total_added += ingest_seed_cves(args.dry_run)
        total_added += ingest_payloads_allthethings(args.dry_run)
        total_added += fetch_nvd_cves(args.cve_count, args.dry_run)

    elapsed = time.time() - start_time
    print(f"\n{'='*40}")
    print(f"Bootstrap tamamlandı: {total_added} kayıt, {elapsed:.1f}s")

    if not args.dry_run:
        print_stats()


if __name__ == "__main__":
    main()
