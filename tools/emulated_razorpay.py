

import argparse
import base64
import hashlib
import hmac
import json
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs


class EmulatedRazorpay:
    def __init__(self, key_id: str, key_secret: str, webhook_secret: str,
                 webhook_url: str):
        self.key_id = key_id
        self.key_secret = key_secret
        self.webhook_secret = webhook_secret
        self.webhook_url = webhook_url
        self.payments: dict[str, dict] = {}
        self.refunds: dict[str, dict] = {}
        self.request_log: list[dict] = []
        self.lock = threading.Lock()
        self._refund_seq = 0

    def register_payment(self, payment_id: str, amount_in_paise: int,
                         currency: str = "INR", status: str = "captured",
                         merchant_id: str = "mid_emulated") -> None:
        self.payments[payment_id] = {
            "id": payment_id, "entity": "payment",
            "amount": amount_in_paise, "currency": currency,
            "status": status, "merchant_id": merchant_id,
        }

    def _auth_ok(self, handler) -> bool:
        raw = handler.headers.get("Authorization", "")
        if not raw.startswith("Basic "):
            return False
        try:
            decoded = base64.b64decode(raw[6:]).decode()
            user, _, pw = decoded.partition(":")
        except Exception:
            return False
        return (hmac.compare_digest(user, self.key_id)
                and hmac.compare_digest(pw, self.key_secret))

    def _make_refund(self, body: dict) -> tuple[int, dict]:
      
        pay = self.payments.get(body.get("payment_id", ""))
        try:
            amount = int(body.get("amount", 0))
        except (TypeError, ValueError, OverflowError):
            return 400, {"error": {"description": "amount must be an integer"}}
        # Round-3: the cap check AND the refund insertion happen under the
        # lock (ThreadingHTTPServer serves concurrent requests) — otherwise
        # two simultaneous refunds can both pass the cap (TOCTOU).
        with self.lock:
            cum = sum(r["amount"] for r in self.refunds.values()
                      if r.get("payment_id") == body.get("payment_id"))
            if pay is not None and cum + amount > pay["amount"]:
                return 409, {"error": {"description":
                    f"refund amount exceeds payment amount "
                    f"(already refunded {cum} of {pay['amount']})"}}
            self._refund_seq += 1
            ref = f"rfnd_emu{self._refund_seq:05d}"
            refund = {
                "id": ref, "entity": "refund",
                "payment_id": body.get("payment_id"),
                "amount": amount,
                "currency": body.get("currency", "INR"),
                "status": "processed",
                "notes": body.get("notes") or {},
            }
            self.refunds[ref] = refund
            if pay is not None:
               
                pay["status"] = (
                    "refunded" if cum + amount >= pay["amount"]
                    else "partially_refunded"
                )
        # Deliver the signed webhook, Razorpay-style, off the request thread.
        if self.webhook_url and self.webhook_secret:
            threading.Thread(target=self._deliver_webhook, args=(refund,),
                             daemon=True).start()
        return 201, refund

    def _deliver_webhook(self, refund: dict) -> None:
        event = {
            "id": f"evt_{refund['id']}",
            "event": "refund.created",
            "created_at": 0,
            "payload": {"refund": {"entity": dict(refund)}},
        }
        raw = json.dumps(event).encode()
        sig = hmac.new(self.webhook_secret.encode(), raw, hashlib.sha256).hexdigest()
        req = urllib.request.Request(
            self.webhook_url, data=raw, method="POST",
            headers={"Content-Type": "application/json",
                     "x-razorpay-signature": sig},
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                r.read()
        except Exception:
            pass  


def make_handler(emu: EmulatedRazorpay):
    class Handler(BaseHTTPRequestHandler):
        def _send(self, code: int, obj: dict) -> None:
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
           
            if self.path == "/_control":
                with emu.lock:
                    self._send(200, {
                        "request_log": emu.request_log,
                        "refunds": dict(emu.refunds),
                        "payments": {k: dict(v) for k, v in emu.payments.items()},
                    })
                return
            emu.request_log.append({"method": "GET", "path": self.path})
            if not emu._auth_ok(self):
                self._send(401, {"error": {"description": "authentication failed"}})
                return
            if self.path.startswith("/v1/payments/"):
                pid = self.path.rsplit("/", 1)[-1]
                pay = emu.payments.get(pid)
                if pay is None:
                    self._send(404, {"error": {"description": "payment not found"}})
                    return
                self._send(200, pay)
            else:
                self._send(404, {"error": {"description": "not found"}})

        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(n)
            emu.request_log.append({"method": "POST", "path": self.path,
                                    "body": raw.decode(errors="replace")})
            if not emu._auth_ok(self):
                self._send(401, {"error": {"description": "authentication failed"}})
                return
            if self.path == "/v1/refunds":
                try:
                    body = json.loads(raw)
                except json.JSONDecodeError:
                    self._send(400, {"error": {"description": "invalid JSON"}})
                    return
                
                if not isinstance(body, dict):
                    self._send(400, {"error": {"description": "body must be a JSON object"}})
                    return
                if body.get("payment_id") not in emu.payments:
                    self._send(404, {"error": {"description": "payment not found"}})
                    return
                status, obj = emu._make_refund(body)
                self._send(status, obj)
            else:
                self._send(404, {"error": {"description": "not found"}})

        def log_message(self, *a):
            pass

    return Handler


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8280)
    ap.add_argument("--key-id", required=True)
    ap.add_argument("--key-secret", required=True)
    ap.add_argument("--payment", action="append", default=[],
                    help="payment_id:amount_in_paise (repeatable)")
    ap.add_argument("--webhook-secret", default="")
    ap.add_argument("--webhook-url", default="")
    args = ap.parse_args()

    emu = EmulatedRazorpay(args.key_id, args.key_secret,
                           args.webhook_secret, args.webhook_url)
    for spec in args.payment:
        pid, _, amount = spec.partition(":")
        emu.register_payment(pid, int(amount))

    server = ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(emu))
    print(f"emulated-razorpay on :{args.port} payments={list(emu.payments)}")
    server.serve_forever()


if __name__ == "__main__":
    main()
