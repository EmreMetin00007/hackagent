#!/usr/bin/env python3
"""
HackerAgent Recon Daemon (Phase C)
Bu script hedef üzerinde sürekli bir (delta) tarama yapar.
Orkestratör oturumu sırasında arkaplanda (veya MCP aracı üzerinden) çalıştırılmak üzere tasarlanmıştır.

Kullanım:
    python recon_daemon.py --target example.com --interval 60
"""

import argparse
import time
import sqlite3
import subprocess
import os
import sys

HACKERAGENT_HOME = os.environ.get("HACKERAGENT_HOME", os.path.expanduser("~/.hackeragent"))
DB_PATH = os.path.join(HACKERAGENT_HOME, "agent_memory.db")

def get_known_ports(target):
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT url_or_port FROM endpoints WHERE target LIKE ? AND protocol='tcp'", (f"%{target}%",))
        ports = {row[0] for row in c.fetchall()}
        conn.close()
        return ports
    except Exception:
        return set()

def save_new_port(target, port, state):
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("INSERT INTO endpoints (target, url_or_port, protocol, state) VALUES (?, ?, 'tcp', ?)", 
                  (target, str(port), state))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"HATA Veritabanı kaydı başarısız: {e}")

def run_nmap_quick(target):
    """Hızlı top-ports taraması yapar ve açık port listesini (set formatında) döndürür."""
    cmd = ["nmap", "--top-ports", "100", "-T4", "--open", target]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        open_ports = set()
        for line in result.stdout.split('\n'):
            if "/tcp" in line and "open" in line:
                port = line.split('/')[0].strip()
                open_ports.add(port)
        return open_ports
    except Exception as e:
        print(f"Nmap hatası: {e}")
        return set()

def daemon_loop(target, interval):
    print(f"[*] Recon Daemon başlatıldı. Hedef: {target}. {interval} saniyede bir tarama yapılacak.")
    print(f"[*] Memory veritabanı: {DB_PATH}")
    
    while True:
        print(f"[{time.strftime('%H:%M:%S')}] Tarama başlatılıyor...")
        known_ports = get_known_ports(target)
        current_ports = run_nmap_quick(target)
        
        # Delta Hesaplama
        new_ports = current_ports - known_ports
        dropped_ports = known_ports - current_ports
        
        if new_ports:
            print(f"[!] DİKKAT: Yeni açık port(lar) bulundu: {new_ports}")
            for p in new_ports:
                save_new_port(target, p, "open")
                print(f"[+] Memory güncellendi (Port eklendi: {p})")
        
        if dropped_ports:
            print(f"[-] Bilgi: Daha önce açık olan portlar artık kapalı: {dropped_ports}")
            
        if not new_ports and not dropped_ports:
            print("[-] Değişiklik yok (Delta 0).")
            
        time.sleep(interval)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="HackerAgent Recon Daemon")
    parser.add_argument("--target", required=True, help="Taranacak hedef IP/Domain")
    parser.add_argument("--interval", type=int, default=120, help="Tarama aralığı (saniye)")
    args = parser.parse_args()
    
    # DB kontrolü
    if not os.path.exists(DB_PATH):
        print("HATA: mcp-memory-server veritabanı bulunamadı. Lütfen önce memory sistemini başlatın.")
        sys.exit(1)
        
    try:
        daemon_loop(args.target, args.interval)
    except KeyboardInterrupt:
        print("\n[*] Recon Daemon durduruldu.")
