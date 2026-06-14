#!/usr/bin/env python3
"""
CCO Vuln Lab — kasıtlı zafiyetli, LOOPBACK-ONLY test hedefi (yetkili).
=====================================================================
SADECE 127.0.0.1'e bağlanır; gerçek bir hedefe DOKUNMAZ. `auto_fanout_variants(live=True)`
ve erişim-kontrolü zincirini güvenle doğrulamak için tasarlanmış bilinçli-zafiyetli uygulama.

Zafiyetler (eğitim amaçlı):
  • GET /search?q=        → yansıyan XSS (q escape edilmeden basılır)
  • GET /item?id=         → hata-tabanlı SQLi (tek tırnak → sahte SQL hata imzası)
  • GET /api/orders/<id>  → BOLA: Authorization header'ı YOK SAYILIR, herkes her order'ı görür
  • GET /admin/export     → BFLA/unauth: token olmadan 200 + hassas veri
  • GET /checkout?price=&quantity= → iş mantığı: negatif fiyat/miktar kabul edilir

Kullanım:  python3 vuln_lab.py [port]     (port 0 → rastgele)
"""
import sys
import json
import html
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

# sahte veri — order'lar farklı kullanıcılara ait (BOLA kanıtı için sahip işaretçileri)
ORDERS = {
    "1001": {"owner": "userA", "email": "alice@lab.local", "total": 250, "item": "Laptop"},
    "1002": {"owner": "userB", "email": "bob@lab.local", "total": 99, "item": "Mouse"},
    "1003": {"owner": "userC", "email": "carol@lab.local", "total": 12, "item": "Cable"},
}


class LabHandler(BaseHTTPRequestHandler):
    server_version = "VulnLab/1.0"

    def _send(self, code, body, ctype="text/html", extra_headers=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query, keep_blank_values=True)
        path = u.path

        # --- 1) Yansıyan XSS ---
        if path == "/search":
            term = (q.get("q") or [""])[0]
            # ZAFİYET: escape YOK
            self._send(200, f"<html><body><h1>Arama</h1><p>Sonuç: {term}</p></body></html>")
            return

        # --- 2) Hata-tabanlı SQLi ---
        if path == "/item":
            iid = (q.get("id") or [""])[0]
            if "'" in iid or '"' in iid:
                # ZAFİYET: ham SQL hatası sızdırır
                self._send(500, "<b>Database error:</b> You have an error in your SQL syntax; "
                                "check the manual near '%s'" % html.escape(iid))
                return
            self._send(200, f"<html><body>Ürün #{html.escape(iid)}: Widget</body></html>")
            return

        # --- 3) BOLA (object-level authz yok) ---
        if path.startswith("/api/orders/"):
            oid = path.rsplit("/", 1)[-1]
            order = ORDERS.get(oid)
            if not order:
                self._send(404, json.dumps({"error": "not found"}), "application/json")
                return
            # ZAFİYET: Authorization header'ı doğrulanmıyor → herkes her order'ı görür
            self._send(200, json.dumps(order), "application/json")
            return

        # --- 4) BFLA / unauth admin ---
        if path == "/admin/export":
            # ZAFİYET: token kontrolü yok → herkes tüm veriyi export eder
            self._send(200, json.dumps({"export": list(ORDERS.values()),
                                        "secret": "all-customer-pii"}), "application/json")
            return

        # --- 5) İş mantığı: negatif fiyat/miktar ---
        if path == "/checkout":
            try:
                price = float((q.get("price") or ["0"])[0])
                qty = int((q.get("quantity") or ["1"])[0])
            except ValueError:
                self._send(400, json.dumps({"error": "bad params"}), "application/json")
                return
            total = price * qty  # ZAFİYET: negatif/sıfır doğrulaması yok
            self._send(200, json.dumps({"price": price, "quantity": qty, "total": total,
                                        "charged": total}), "application/json")
            return

        if path == "/":
            self._send(200, "<html><body>VulnLab — /search /item /api/orders/<id> "
                            "/admin/export /checkout</body></html>")
            return
        self._send(404, "<html>404</html>")

    def log_message(self, *a):
        pass


def serve(port=0):
    srv = ThreadingHTTPServer(("127.0.0.1", port), LabHandler)
    return srv


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8899
    srv = serve(port)
    print(f"VulnLab → http://127.0.0.1:{srv.server_address[1]}  (Ctrl-C ile durdur)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.shutdown()
