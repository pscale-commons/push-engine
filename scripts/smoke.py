#!/usr/bin/env python3
"""smoke.py — the engine's acceptance battery, no network beyond localhost.

A stateful mock beach (blocks, locks, create-locked, the probe semantics) plus
a recording sink for fanout and ntfy stands in for the world; the engine runs
as a subprocess against it. Every law the engine claims is asserted here:
auth, dedup, the locked-block gate, create-locked founding, all three
patterns, channel delivery, rate-limit suppression with the fold-in counter,
and bus fidelity (fanout bytes identical to what arrived).

Run: python3 scripts/smoke.py
"""
import json
import os
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MOCK_PORT, ENGINE_PORT = 8931, 8932
SECRET = "smoke-shared-secret"

# ── the mock beach + sinks ──────────────────────────────────────────────────

BLOCKS = {
    "ear:testa": {
        "_": "What testa hears about.",
        "1": {"_": "parlour", "1": "parlour", "3": "all"},
        "2": {"_": "named", "1": "named", "2": "testa", "3": "all"},
        "3": {"_": "watching the gate", "1": "located", "2": "pool:urb 33",
              "3": "all"},
    },
    "ear:openhand": {"_": "An ear left unlocked."},
    "pool:testa": {"7": {"_": "a quiet hello for the parlour", "1": "visitor",
                          "2": "", "3": "2026-08-17T09:00:00Z"}},
    "pool:town": {"4": {"_": "does anyone know testa around here?",
                         "1": "asker", "2": "", "3": "2026-08-17T09:01:00Z"}},
    "pool:urb": {"9": {"_": "the gate creaks open", "1": "keeper",
                        "2": "3.3", "3": "2026-08-17T09:02:00Z"},
                 "8": {"_": "far away, nothing", "1": "keeper",
                        "2": "7.1", "3": "2026-08-17T09:03:00Z"}},
}
LOCKS = {"ear:testa": "key-testa"}
HITS = {"fanout": [], "ntfy": []}


class Mock(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        name = (q.get("block") or [""])[0]
        spindle = (q.get("spindle") or [""])[0]
        if u.path != "/.well-known/pscale-beach" or not name:
            return self._send(404, {"error": "not found"})
        block = BLOCKS.get(name)
        if block is None:
            return self._send(404, {"error": "block not found"})
        if spindle:  # the wire returns the raw node at a spindle
            node = block.get(spindle.split(".")[0])
            if node is None:
                return self._send(404, {"error": "no such position"})
            return self._send(200, node)
        return self._send(200, block)

    def do_POST(self):
        u = urlparse(self.path)
        raw = self.rfile.read(int(self.headers.get("content-length", "0")))
        if u.path == "/ring":  # the fanout sink — record exact bytes + header
            HITS["fanout"].append(
                (raw, self.headers.get("x-pool-webhook-secret", "")))
            return self._send(200, {"rung": False, "reason": "sink"})
        if u.path == "/ntfy":  # the ntfy sink — JSON publish mode
            HITS["ntfy"].append(json.loads(raw.decode()))
            return self._send(200, {"id": "smoke"})
        if u.path != "/.well-known/pscale-beach":
            return self._send(404, {"error": "not found"})
        q = parse_qs(u.query)
        name = (q.get("block") or [""])[0]
        body = json.loads(raw.decode() or "{}")
        new_lock = body.get("new_lock")
        secret = body.get("secret")
        if name not in BLOCKS:
            if new_lock:  # R1 — create locked, no secret needed
                BLOCKS[name] = body.get("content") or {}
                LOCKS[name] = new_lock
                return self._send(200, {"ok": True, "created": True})
            return self._send(404, {"error": "block not found"})
        lock = LOCKS.get(name)
        if lock is None:
            return self._send(200, {"ok": True, "open": True})
        if secret != lock:
            return self._send(403, {"error": "secret does not match"})
        return self._send(200, {"ok": True})


def http(method, url, body=None, headers=None):
    req = urllib.request.Request(url, method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"content-type": "application/json",
                                          **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode() or "{}")


PASS, FAIL = 0, 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("  ok  %s" % name)
    else:
        FAIL += 1
        print("  FAIL %s %s" % (name, detail))


def wait_deliveries(n, kind="ntfy", timeout=5.0):
    t0 = time.time()
    while time.time() - t0 < timeout:
        if len(HITS[kind]) >= n:
            return True
        time.sleep(0.05)
    return False


def main():
    mock = ThreadingHTTPServer(("127.0.0.1", MOCK_PORT), Mock)
    threading.Thread(target=mock.serve_forever, daemon=True).start()

    store = os.path.join(BASE, ".smoke-store.json")
    if os.path.exists(store):
        os.remove(store)
    env = dict(os.environ,
               ENGINE_SECRET=SECRET,
               BEACH="http://127.0.0.1:%d" % MOCK_PORT,
               FANOUT_URLS="http://127.0.0.1:%d/ring" % MOCK_PORT,
               ENGINE_STORE=store,
               PORT=str(ENGINE_PORT),
               EMAIL_MIN_S="600", PUSH_MIN_S="2",
               GMAIL_ADDRESS="", GMAIL_APP_PASSWORD="",
               VAPID_PRIVATE="", VAPID_PUBLIC="")
    engine = subprocess.Popen([sys.executable, os.path.join(BASE, "engine.py")],
                              env=env)
    E = "http://127.0.0.1:%d" % ENGINE_PORT
    try:
        for _ in range(50):
            try:
                code, h = http("GET", E + "/health")
                if code == 200:
                    break
            except Exception:
                time.sleep(0.1)
        else:
            print("engine never came up")
            sys.exit(1)

        print("auth and health")
        check("health ok", h.get("ok") is True)
        code, _ = http("POST", E + "/event", {"pool": "pool:testa", "slot": "7"})
        check("event without secret refused", code == 403)

        print("enrolment — proof, gate, founding")
        code, r = http("POST", E + "/enroll",
                       {"handle": "testa", "passphrase": "wrong-key",
                        "ntfy": "http://127.0.0.1:%d/ntfy/t-testa" % MOCK_PORT})
        check("wrong key refused", code == 403, str(r))
        code, r = http("POST", E + "/enroll",
                       {"handle": "testa", "passphrase": "key-testa",
                        "ntfy": "http://127.0.0.1:%d/ntfy/t-testa" % MOCK_PORT})
        check("true key enrols", code == 200 and "ntfy" in r.get("detail", ""), str(r))
        code, r = http("POST", E + "/enroll",
                       {"handle": "openhand", "passphrase": "any",
                        "ntfy": "http://127.0.0.1:%d/ntfy/t-open" % MOCK_PORT})
        check("unlocked ear refused", code == 403 and "not locked" in r.get("detail", ""), str(r))
        code, r = http("POST", E + "/enroll",
                       {"handle": "fresh", "passphrase": "fresh-key",
                        "ntfy": "http://127.0.0.1:%d/ntfy/t-fresh" % MOCK_PORT})
        check("absent ear founded locked", code == 200 and LOCKS.get("ear:fresh") == "fresh-key", str(r))
        check("founded ear carries parlour+named",
              str(BLOCKS.get("ear:fresh", {}).get("1", {}).get("1")) == "parlour"
              and str(BLOCKS.get("ear:fresh", {}).get("2", {}).get("2")) == "fresh")

        print("events — patterns, dedup, bus fidelity")
        ev = {"origin": "127.0.0.1:%d" % MOCK_PORT, "pool": "pool:testa",
              "slot": "7", "agent_id": "visitor", "ts": "2026-08-17T09:00:00Z"}
        code, r = http("POST", E + "/event", ev,
                       {"x-pool-webhook-secret": SECRET})
        check("event accepted", code == 200 and r.get("ok"), str(r))
        check("parlour notified", wait_deliveries(1),
              "ntfy hits: %d" % len(HITS["ntfy"]))
        if HITS["ntfy"]:
            n = HITS["ntfy"][0]
            check("note quotes the voice", "quiet hello" in n.get("message", ""), str(n))
            check("note topic routed", n.get("topic") == "t-testa", str(n))
        check("fanout got exact bytes",
              len(HITS["fanout"]) == 1
              and json.loads(HITS["fanout"][0][0].decode()) == ev
              and HITS["fanout"][0][1] == SECRET)
        code, r = http("POST", E + "/event", ev,
                       {"x-pool-webhook-secret": SECRET})
        check("replay deduped", code == 200 and r.get("dedup") is True, str(r))
        time.sleep(0.3)
        check("dedup delivered nothing new", len(HITS["ntfy"]) == 1)
        check("dedup fanned out nothing new", len(HITS["fanout"]) == 1)

        print("named + located + rate manners")
        time.sleep(2.1)  # clear the 2s push window
        code, r = http("POST", E + "/event",
                       {"origin": "127.0.0.1:%d" % MOCK_PORT, "pool": "pool:town",
                        "slot": "4", "agent_id": "asker", "ts": "t"},
                       {"x-pool-webhook-secret": SECRET})
        check("named matched", wait_deliveries(2), "hits %d" % len(HITS["ntfy"]))
        if len(HITS["ntfy"]) >= 2:
            check("named reason present", "named" in HITS["ntfy"][1].get("message", ""),
                  str(HITS["ntfy"][1]))
        code, r = http("POST", E + "/event",
                       {"origin": "127.0.0.1:%d" % MOCK_PORT, "pool": "pool:urb",
                        "slot": "9", "agent_id": "keeper", "ts": "t"},
                       {"x-pool-webhook-secret": SECRET})
        time.sleep(0.4)
        check("located inside window suppressed (counted, not sent)",
              len(HITS["ntfy"]) == 2)
        code, r = http("POST", E + "/event",
                       {"origin": "127.0.0.1:%d" % MOCK_PORT, "pool": "pool:urb",
                        "slot": "8", "agent_id": "keeper", "ts": "t"},
                       {"x-pool-webhook-secret": SECRET})
        time.sleep(0.4)
        check("prefix 71 does not match watch 33 (no note, no count)",
              len(HITS["ntfy"]) == 2)
        time.sleep(2.1)
        code, r = http("POST", E + "/event",
                       {"origin": "127.0.0.1:%d" % MOCK_PORT, "pool": "pool:urb",
                        "slot": "9", "agent_id": "keeper", "ts": "t2"},
                       {"x-pool-webhook-secret": SECRET})
        # same slot again would dedup — bump the slot to a fresh landing
        code, r = http("POST", E + "/event",
                       {"origin": "127.0.0.1:%d" % MOCK_PORT, "pool": "pool:urb",
                        "slot": "9.1", "agent_id": "keeper", "ts": "t3"},
                       {"x-pool-webhook-secret": SECRET})
        check("held note folds into the next (+1 earlier)",
              wait_deliveries(3) and "+1 earlier" in HITS["ntfy"][2].get("message", ""),
              str(HITS["ntfy"][-1:]))

        print("foreign origin + removal")
        code, r = http("POST", E + "/event",
                       {"origin": "https://elsewhere.example", "pool": "pool:testa",
                        "slot": "7", "agent_id": "x", "ts": "t"},
                       {"x-pool-webhook-secret": SECRET})
        check("foreign origin ignored", r.get("ignored") == "foreign origin", str(r))
        code, r = http("DELETE", E + "/enroll",
                       {"handle": "testa", "passphrase": "key-testa"})
        check("removal by proof", code == 200 and "removed" in r.get("detail", ""), str(r))
    finally:
        engine.terminate()
        mock.shutdown()
        if os.path.exists(store):
            os.remove(store)

    print("\n%d passed, %d failed" % (PASS, FAIL))
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
