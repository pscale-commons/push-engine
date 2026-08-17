#!/usr/bin/env python3
"""push-engine — the beach reaches people. One machine, zero LLM, forever.

A beach-crab at rung 0 of the ladder (bsp-mcp docs/beach-crab-ladder.md),
event-driven: receive event -> match subscriptions -> deliver on channels.
Design: bsp-mcp proposals/2026-08-14-push-engine.md (merged). The division of
labour is one sentence: agents get woken (the waker's lane); humans get
notified (this service's). No LLM ever runs here — pattern-matching is string
and digit-walk work, a notification is formatting plus transport — which is
why it is cheap, always-on, and has no injection surface: events are data
moving through machine rules, and pool text is QUOTED into a note, never
interpreted, never rendered as markup.

THE BUS. The beach fires one webhook per landed pool voice (pscale-beach #62:
POST {origin, pool, slot, agent_id, ts}, shared secret in the
x-pool-webhook-secret header, fire-and-forget, no retries). This service is
built to BE the beach's single webhook target (engine-as-bus): every event
received at /event is forwarded verbatim to FANOUT_URLS (the waker first)
before any matching happens, so downstream services see exactly what the
beach fired. Until the cutover it simply receives the waker's forwarded
feed — same wire either way. A small dedup on (origin, pool, slot) makes the
transition loop-safe by construction: an event that arrives twice — waker
forward plus direct declaration, or any accidental cycle — fans out and
matches once.

SUBSCRIPTIONS ARE PUBLIC BLOCKS. What a person watches is their own auditable
declaration at ear:<handle> on the beach, in their own locked block — put the
shell to your ear. Three machine patterns (v1, extended only by need):
  parlour — a voice lands in pool:<my-handle>
  named   — my name (or a chosen word) appears in a landed voicing's text
  located — a voice lands bearing an address-of-attention under a digit-walk
            prefix I watch (the same prefix logic located pools use)
Each digit position of ear:<handle> is one subscription:
  {_: the human sentence, 1: kind, 2: parameter, 3: channel kinds}.
Field 3 names channel KINDS only ("email", "ntfy", "webpush", "all") — never
an address. An address in a public block is a spam harvest.

CHANNELS ARE PRIVATE, SERVICE-SIDE. Where a person is reached lives only in
this service's store, enrolled and removed by PROOF against the beach's own
locks: the holder POSTs {handle, passphrase, email?|ntfy?|webpush?} and the
engine writes ear:<handle>'s root sentence back to itself byte-identical
under the supplied secret — only the true key passes a locked block, so a
wrong key cannot enrol. An UNLOCKED ear block proves nothing, so it is
refused (the probe: the same write-back with no secret succeeding = open).
When no ear block exists yet, the same POST creates a default one LOCKED
under the supplied passphrase (create-locked is the substrate's own R1) —
the whole flow is one act: the holder types where to be reached, once.
Unlike the waker, this service stores NO passphrase: proof happens at the
door and only the channel addresses are kept (volume file, mode 600 — the
same trust envelope as this process's env). The engine never asks anyone to
subscribe; every email carries the standing line.

MANNERS. Per (handle, channel) minimum interval; events suppressed inside
the window are counted and folded into the next note ("+N earlier") — a hot
room becomes one line, never forty. No clocks, no timers, no digests queued:
the counter rides the next event, and silence costs nothing.

Env: ENGINE_SECRET (shared with the beach's POOL_WEBHOOK_SECRET — the same
secret rides the whole chain); BEACH (pinned origin, default
https://beach.happyseaurchin.com); FANOUT_URLS (comma list — the waker's
/ring at cutover; empty = no fanout); ENGINE_STORE (default
/data/enrolments.json); GMAIL_ADDRESS + GMAIL_APP_PASSWORD (the central
sender — the beach's own address); MIRROR_URL (where a note's link lands,
default https://mirror.onen.ai/mirror); NTFY_BASE (default https://ntfy.sh);
VAPID_PRIVATE + VAPID_PUBLIC (base64url, scripts/gen-vapid.py) + VAPID_SUB
(mailto:); EMAIL_MIN_S (default 600) + PUSH_MIN_S (default 120); PORT.
"""
import base64
import hmac
import json
import os
import re
import socket
import struct
import threading
import time
import urllib.error
import urllib.request
import zlib

# Railway egress quirk: some destinations resolve AAAA-first and the container
# cannot route IPv6 (Errno 101 to ntfy.sh, observed live 2026-08-17). Prefer
# IPv4 for every outbound call; fall through untouched when only v6 exists.
_orig_getaddrinfo = socket.getaddrinfo

def _v4_first(host, port, family=0, *args, **kw):
    res = _orig_getaddrinfo(host, port, family, *args, **kw)
    v4 = [r for r in res if r[0] == socket.AF_INET]
    return v4 or res

socket.getaddrinfo = _v4_first
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import quote

try:  # the one channel that needs real crypto; absent = webpush disabled
    from pywebpush import webpush, WebPushException
except ImportError:  # pragma: no cover
    webpush, WebPushException = None, Exception

ENGINE_SECRET = os.environ.get("ENGINE_SECRET", "")
BEACH = os.environ.get("BEACH", "https://beach.happyseaurchin.com").rstrip("/")
FANOUT_URLS = [u.strip() for u in os.environ.get("FANOUT_URLS", "").split(",") if u.strip()]
STORE_PATH = os.environ.get("ENGINE_STORE", "/data/enrolments.json")
GMAIL_ADDRESS = os.environ.get("GMAIL_ADDRESS", "")
GMAIL_APP_PASSWORD = os.environ.get("GMAIL_APP_PASSWORD", "")
MIRROR_URL = os.environ.get("MIRROR_URL", "https://mirror.onen.ai/mirror")
NTFY_BASE = os.environ.get("NTFY_BASE", "https://ntfy.sh").rstrip("/")
VAPID_PRIVATE = os.environ.get("VAPID_PRIVATE", "")
VAPID_PUBLIC = os.environ.get("VAPID_PUBLIC", "")
VAPID_SUB = os.environ.get("VAPID_SUB", "mailto:beach@happyseaurchin.com")
EMAIL_MIN_S = int(os.environ.get("EMAIL_MIN_S", "600"))
PUSH_MIN_S = int(os.environ.get("PUSH_MIN_S", "120"))
VERIFY_FAILS_MAX = 5  # failed passphrase proofs per handle per hour -> 429

WEBPUSH_READY = bool(webpush and VAPID_PRIVATE and VAPID_PUBLIC)
# Stamped once per process — /health carries it so a deploy-wait can tell the
# new process from the old one (both answer healthy during the swap).
BOOT_TS = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

_seen = {}            # dedup: event key -> monotonic ts (pruned by size)
_SEEN_MAX = 512
_ear_cache = {}       # handle -> (monotonic ts, block dict|None)
_EAR_TTL_S = 60
_last_sent = {}       # (handle, channel-kind) -> monotonic ts
_suppressed = {}      # (handle, channel-kind) -> count held back in-window
_verify_fails = {}    # handle -> [monotonic ts of failed proofs]
_store_lock = threading.Lock()


def log(msg):
    print("[engine] %s" % msg, flush=True)


def host_of(origin):
    """Origins compare as bare hosts (the beach reports its Host-header form,
    the pin is written as a URL — both normalize here; waker precedent)."""
    o = origin.strip().lower()
    for p in ("https://", "http://"):
        if o.startswith(p):
            o = o[len(p):]
    return o.rstrip("/")


def digits_of(addr):
    """A pscale address reduced to its digit walk — '3.3' and '33' and '3,3'
    are the same position; prefix matching runs on this form."""
    return re.sub(r"\D", "", str(addr or ""))


# ── the store (channels only — no passphrase is ever kept) ─────────────────

def _store_load():
    try:
        with open(STORE_PATH) as f:
            return json.load(f)
    except Exception:
        return {}


def _store_save(store):
    d = os.path.dirname(STORE_PATH)
    if d:
        try:
            os.makedirs(d, exist_ok=True)
        except OSError:
            pass
    tmp = STORE_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(store, f, indent=2)
    os.replace(tmp, STORE_PATH)
    try:
        os.chmod(STORE_PATH, 0o600)
    except OSError:
        pass


# ── beach I/O (stdlib; reads plus the byte-identical proof write) ──────────

def beach_get(block, spindle=None):
    """Raw node at the block (or at the spindle within it) — the wire returns
    the node itself on a spindle GET; a whole-block GET may wrap in {block}."""
    url = "%s/.well-known/pscale-beach?block=%s" % (BEACH, quote(block))
    if spindle:
        url += "&spindle=%s" % quote(str(spindle))
    with urllib.request.urlopen(urllib.request.Request(url), timeout=10) as r:
        d = json.loads(r.read().decode())
    if isinstance(d, dict) and "block" in d and not spindle:
        return d["block"]
    return d


def beach_post(body):
    req = urllib.request.Request(
        "%s/.well-known/pscale-beach?block=%s" % (BEACH, quote(body["block"])),
        data=json.dumps(body).encode(),
        headers={"content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read().decode())


# ── enrolment — proof against the beach's own locks, nothing kept but where ─

def _throttled(handle):
    now = time.monotonic()
    fails = [t for t in _verify_fails.get(handle, []) if now - t < 3600]
    _verify_fails[handle] = fails
    return len(fails) >= VERIFY_FAILS_MAX


def default_ear(handle):
    """The ear a first arrival is born with: parlour plus own name, the two
    subscriptions almost everyone means. Positions 3-9 stay open for the
    holder's own hand (located watches and more), edited with the same key."""
    return {
        "_": ("What %s hears about from this beach — each digit position one "
              "subscription, machine-read by the push engine; where to reach "
              "me lives at the engine by proof, never here. Shapes and law: "
              "ways:push at this beach." % handle),
        "1": {"_": "A voice landing in my parlour reaches me.",
              "1": "parlour", "3": "all"},
        "2": {"_": "My name voiced in any pool here reaches me.",
              "1": "named", "2": handle, "3": "all"},
    }


def prove_or_found(handle, passphrase):
    """(ok, reason). Three states of ear:<handle>:
    absent   -> create the default ear LOCKED under the passphrase (R1 — the
                holder's first arrival is one act);
    locked   -> write its root sentence back byte-identical under the
                passphrase (only the true key passes);
    unlocked -> refused. An open block proves nothing; the probe is the same
                write-back with NO secret succeeding. The holder locks it
                whole with their own key, then returns."""
    block = "ear:%s" % handle
    try:
        ear = beach_get(block)
    except urllib.error.HTTPError as e:
        if e.code != 404:
            return False, "beach refused the read: HTTP %d" % e.code
        ear = None
    except Exception as e:
        return False, "beach unreachable: %s" % str(e)[:60]

    if not isinstance(ear, dict) or not ear:
        try:
            beach_post({"block": block, "content": default_ear(handle),
                        "new_lock": passphrase})
            _ear_cache.pop(handle, None)
            return True, "ear:%s founded and locked under your key" % handle
        except urllib.error.HTTPError as e:
            return False, "founding refused: HTTP %d" % e.code
        except Exception as e:
            return False, "founding failed: %s" % str(e)[:60]

    root = ear.get("_")
    if not isinstance(root, str) or not root.strip():
        return False, ("ear:%s has no root sentence to prove against — give "
                       "the block a plain '_' line, locked, then return" % handle)
    try:  # the locked-block gate: an open block accepts a secretless write
        beach_post({"block": block, "spindle": "0", "content": root})
        return False, ("ear:%s is not locked — an open block proves nothing. "
                       "Lock it whole with your own key (new_lock, no "
                       "spindle), then enrol again" % handle)
    except urllib.error.HTTPError as e:
        if e.code not in (401, 403):
            return False, "beach refused the probe: HTTP %d" % e.code
    except Exception as e:
        return False, "probe failed: %s" % str(e)[:60]
    try:  # the proof proper — byte-identical, mutates nothing, no new_lock ever
        beach_post({"block": block, "spindle": "0", "content": root,
                    "secret": passphrase})
        return True, "proven against ear:%s's own lock" % handle
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            _verify_fails.setdefault(handle, []).append(time.monotonic())
            return False, "passphrase does not open ear:%s" % handle
        return False, "beach refused the proof: HTTP %d" % e.code
    except Exception as e:
        return False, "proof failed: %s" % str(e)[:60]


# ── the ear — reading what a handle listens for ────────────────────────────

def ear_block(handle):
    now = time.monotonic()
    hit = _ear_cache.get(handle)
    if hit and now - hit[0] < _EAR_TTL_S:
        return hit[1]
    try:
        ear = beach_get("ear:%s" % handle)
        ear = ear if isinstance(ear, dict) else None
    except Exception:
        ear = None
    _ear_cache[handle] = (now, ear)
    return ear


def subscriptions(ear):
    """Digit positions holding {1: kind, ...} — a plain-prose position is a
    note to humans and never machine-read."""
    subs = []
    for k in sorted(k for k in (ear or {}) if k.isdigit() and k != "0"):
        v = ear[k]
        if isinstance(v, dict) and str(v.get("1", "")).strip():
            subs.append(v)
    return subs


def kinds_of(sub):
    raw = str(sub.get("3", "") or "all").strip().lower()
    named = {w for w in re.split(r"[\s,]+", raw) if w}
    return {"email", "ntfy", "webpush"} if ("all" in named or not named) else named


def match(sub, handle, event, entry_text, entry_at):
    """One subscription against one event -> a human reason, or None."""
    kind = str(sub.get("1", "")).strip().lower()
    param = str(sub.get("2", "") or "").strip()
    if kind == "parlour":
        if event["pool"] == "pool:%s" % handle:
            return "a voice in your parlour"
    elif kind == "named":
        needle = (param or handle).lower()
        if needle and needle in (entry_text or "").lower():
            return "named “%s”" % (param or handle)
    elif kind == "located":
        parts = param.split()
        pool_filter, prefix = (parts[0], parts[1] if len(parts) > 1 else "") \
            if parts and parts[0].startswith("pool:") else (None, parts[0] if parts else "")
        if pool_filter and event["pool"] != pool_filter:
            return None
        p, a = digits_of(prefix), digits_of(entry_at)
        if p and a.startswith(p):
            return "movement at %s under your watch (%s)" % (entry_at, param)
    return None


# ── delivery — three channels, one manners law ─────────────────────────────

STANDING_LINE = ("The engine never asks you for anything by email. End or "
                 "change this at any time with your own key: %s/push")


def _held(handle, kind, min_s):
    """The manners law: inside the window the event is counted, not sent;
    the count rides the next note. No timers — silence costs nothing. The
    window closes only on a send that WORKED (_sent marks it) — a failed
    delivery must never silence the retry the next event brings."""
    last = _last_sent.get((handle, kind))
    if last and time.monotonic() - last < min_s:
        _suppressed[(handle, kind)] = _suppressed.get((handle, kind), 0) + 1
        return True
    return False


def _sent(handle, kind):
    _last_sent[(handle, kind)] = time.monotonic()


def _fold_prefix(handle, kind):
    n = _suppressed.pop((handle, kind), 0)
    return ("(+%d earlier notes held back) " % n) if n else ""


def send_email(addr, subject, body):
    import smtplib
    from email.mime.text import MIMEText
    msg = MIMEText(body, _charset="utf-8")
    msg["Subject"] = subject
    msg["From"] = GMAIL_ADDRESS
    msg["To"] = addr
    with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=20) as s:
        s.login(GMAIL_ADDRESS, GMAIL_APP_PASSWORD)
        s.send_message(msg)


def send_ntfy(topic, title, body, url):
    """The public ntfy.sh answers datacenter egress slowly at times — one
    patient attempt, one retry, and a full-URL topic can point anywhere."""
    base, t = (topic.rsplit("/", 1) if "://" in topic else (NTFY_BASE, topic))
    payload = {"topic": t, "title": title, "message": body, "click": url}
    data = json.dumps(payload).encode()
    for attempt in (1, 2):
        try:
            req = urllib.request.Request(
                base, data=data, headers={"content-type": "application/json"})
            with urllib.request.urlopen(req, timeout=25) as r:
                r.read()
            return
        except Exception:
            if attempt == 2:
                raise
            time.sleep(2)


def send_webpush(handle, subs, title, body, url):
    """Push to every device; a gone endpoint (404/410) is pruned in place."""
    keep, pruned = [], 0
    for sub in subs:
        try:
            webpush(subscription_info=sub,
                    data=json.dumps({"title": title, "body": body, "url": url}),
                    vapid_private_key=VAPID_PRIVATE,
                    vapid_claims={"sub": VAPID_SUB}, ttl=60)
            keep.append(sub)
        except WebPushException as e:
            code = getattr(getattr(e, "response", None), "status_code", 0)
            if code in (404, 410):
                pruned += 1
            else:
                keep.append(sub)
                log("webpush to %s failed: %s" % (handle, str(e)[:80]))
        except Exception as e:
            keep.append(sub)
            log("webpush to %s failed: %s" % (handle, str(e)[:80]))
    if pruned:
        with _store_lock:
            s = _store_load()
            if handle in s:
                s[handle]["webpush"] = keep
                _store_save(s)
        log("pruned %d gone webpush endpoint(s) for %s" % (pruned, handle))
    return keep


def deliver(handle, kinds, title, body, url, test=False):
    """One event's note to one handle on the channels both sides named —
    the subscription's kinds intersected with what is enrolled."""
    e = _store_load().get(handle) or {}
    sent = []
    if "email" in kinds and e.get("email") and GMAIL_ADDRESS and GMAIL_APP_PASSWORD:
        if test or not _held(handle, "email", EMAIL_MIN_S):
            try:
                send_email(e["email"], title,
                           "%s%s\n\nRead it where it lives: %s\n\n— the beach push "
                           "engine. You hear this because ear:%s says so, with "
                           "your own key.\n%s"
                           % (_fold_prefix(handle, "email"), body, url, handle,
                              STANDING_LINE % PUBLIC_URL))
                sent.append("email")
                _sent(handle, "email")
            except Exception as ex:
                log("email to %s failed: %s" % (handle, str(ex)[:80]))
    if "ntfy" in kinds and e.get("ntfy"):
        if test or not _held(handle, "ntfy", PUSH_MIN_S):
            try:
                send_ntfy(e["ntfy"], title, _fold_prefix(handle, "ntfy") + body, url)
                sent.append("ntfy")
                _sent(handle, "ntfy")
            except Exception as ex:
                log("ntfy to %s failed: %s" % (handle, str(ex)[:80]))
    if "webpush" in kinds and e.get("webpush") and WEBPUSH_READY:
        if test or not _held(handle, "webpush", PUSH_MIN_S):
            live = send_webpush(handle, e["webpush"], title,
                                _fold_prefix(handle, "webpush") + body, url)
            if live:
                sent.append("webpush")
                _sent(handle, "webpush")
    return sent


# ── the event — dedup, fanout, match, deliver ──────────────────────────────

def fanout(raw):
    """The bus duty, first and verbatim: downstream services see exactly the
    bytes the beach fired, same secret header, fire-and-forget."""
    for u in FANOUT_URLS:
        def _go(url=u):
            try:
                req = urllib.request.Request(
                    url, data=raw,
                    headers={"content-type": "application/json",
                             **({"x-pool-webhook-secret": ENGINE_SECRET}
                                if ENGINE_SECRET else {})})
                with urllib.request.urlopen(req, timeout=5) as r:
                    r.read()
            except Exception as e:
                log("fanout to %s failed: %s" % (url, str(e)[:60]))
        threading.Thread(target=_go, daemon=True).start()


def seen_before(key):
    now = time.monotonic()
    if key in _seen:
        return True
    _seen[key] = now
    if len(_seen) > _SEEN_MAX:  # prune oldest half, no clocks needed
        for k in sorted(_seen, key=_seen.get)[:_SEEN_MAX // 2]:
            _seen.pop(k, None)
    return False


def entry_of(event):
    """The landed voice itself — one raw-node GET; the webhook carries no
    text, so named/located matching reads the slot it names."""
    try:
        node = beach_get(event["pool"], spindle=event["slot"])
    except Exception as e:
        log("slot read failed for %s %s: %s"
            % (event["pool"], event["slot"], str(e)[:60]))
        return "", ""
    if isinstance(node, str):
        return node, ""
    if isinstance(node, dict):
        t = node.get("_")
        return (t if isinstance(t, str) else ""), str(node.get("2", "") or "")
    return "", ""


def match_and_deliver(event):
    handles = sorted(_store_load().keys())
    if not handles:
        return 0
    entry_text, entry_at = None, None  # fetched once, only if a sub needs it
    matched = 0
    for handle in handles:
        if event.get("agent_id") == handle:
            continue  # a voice never notifies its own author
        ear = ear_block(handle)
        if not ear:
            continue
        reasons, kinds = [], set()
        for sub in subscriptions(ear):
            kind = str(sub.get("1", "")).strip().lower()
            if kind in ("named", "located") and entry_text is None:
                entry_text, entry_at = entry_of(event)
            r = match(sub, handle, event, entry_text or "", entry_at or "")
            if r:
                reasons.append(r)
                kinds |= kinds_of(sub)
        if not reasons:
            continue
        matched += 1
        pool_name = event["pool"][len("pool:"):]
        who = event.get("agent_id") or "someone"
        if entry_text is None and any(
                str(s.get("1", "")).lower() == "parlour" for s in subscriptions(ear)):
            entry_text, entry_at = entry_of(event)  # quote the voice in the note
        quote_txt = (entry_text or "").strip()
        if len(quote_txt) > 240:
            quote_txt = quote_txt[:240] + "…"
        title = "%s spoke in %s" % (who, event["pool"])
        body = "%s: %s%s" % ("; ".join(reasons),
                             ("“%s”" % quote_txt) if quote_txt else
                             "(slot %s)" % event["slot"],
                             "")
        url = "%s?pool=%s" % (MIRROR_URL, quote(pool_name))
        sent = deliver(handle, kinds, title, body, url)
        log("notified %s via %s (%s)" % (handle, ",".join(sent) or "nothing-due",
                                         "; ".join(reasons)))
    return matched


# ── the web-push proving ground — served by the engine itself ──────────────
# The mirror is the production door (its own lane); this page settles
# feasibility with zero coupling: one field per channel, the proof inline.

def _png_solid(size=192, rgb=(15, 118, 110)):
    raw = b"".join(b"\x00" + bytes(rgb) * size for _ in range(size))
    def chunk(t, d):
        return (struct.pack(">I", len(d)) + t + d
                + struct.pack(">I", zlib.crc32(t + d) & 0xffffffff))
    ihdr = struct.pack(">IIBBBBB", size, size, 8, 2, 0, 0, 0)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr)
            + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))


_ICON = _png_solid()

MANIFEST = {"name": "the beach, in your ear", "short_name": "beach-ear",
            "start_url": "/push", "display": "standalone",
            "background_color": "#ffffff", "theme_color": "#0f766e",
            "icons": [{"src": "/icon.png", "sizes": "192x192",
                       "type": "image/png"}]}

SW_JS = """\
self.addEventListener('push', function (e) {
  var d = {};
  try { d = e.data.json(); } catch (err) { d = { body: e.data ? e.data.text() : '' }; }
  e.waitUntil(self.registration.showNotification(d.title || 'the beach', {
    body: d.body || '', icon: '/icon.png', data: { url: d.url || '/' }
  }));
});
self.addEventListener('notificationclick', function (e) {
  e.notification.close();
  e.waitUntil(clients.openWindow((e.notification.data && e.notification.data.url) || '/'));
});
"""

PUSH_PAGE = """\
<!doctype html>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="theme-color" content="#0f766e">
<link rel="manifest" href="/manifest.json">
<link rel="apple-touch-icon" href="/icon.png">
<title>the beach, in your ear</title>
<style>
  body { font: 16px/1.5 system-ui, sans-serif; max-width: 34em; margin: 2em auto; padding: 0 1em; color: #1a1a1a; }
  h1 { font-size: 1.3em; color: #0f766e; }
  label { display: block; margin: .8em 0 .2em; font-weight: 600; }
  input { width: 100%; padding: .5em; font-size: 1em; border: 1px solid #bbb; border-radius: 6px; box-sizing: border-box; }
  button { margin: .6em .4em 0 0; padding: .55em 1em; font-size: 1em; border: 0; border-radius: 6px; background: #0f766e; color: #fff; cursor: pointer; }
  button.quiet { background: #64748b; }
  pre { background: #f4f4f5; padding: .8em; border-radius: 6px; white-space: pre-wrap; word-break: break-word; }
  small { color: #555; }
</style>
<h1>the beach, in your ear</h1>
<p>What you hear about is your own public declaration on the beach
(<code>ear:&lt;handle&gt;</code>). <em>Where</em> you are reached lives only here,
proven by your own key, removable the same way. First arrival founds your ear
(parlour + your name) locked under the passphrase you type.</p>
<label>handle</label><input id="h" autocomplete="username" placeholder="e.g. JulieJ">
<label>passphrase (your own edit-latch — proven against the beach, never stored)</label>
<input id="p" type="password" autocomplete="current-password">
<label>email <small>(one address, one field — leave blank to skip)</small></label>
<input id="email" type="email" placeholder="you@example.com">
<label>ntfy topic <small>(the topic you subscribed to in the ntfy app)</small></label>
<input id="ntfy" placeholder="e.g. julie-hears-the-beach-x7">
<p style="margin-bottom:.2em"><strong>Green switches a way of hearing ON.
Grey only checks or undoes.</strong> Every button uses the handle and
passphrase above; setting up is once per channel, per device for push.</p>
<div>
  <button onclick="enrol()">hear by email / ntfy</button>
  <button onclick="push()">get notifications on this device</button>
</div>
<div>
  <button class="quiet" onclick="test()">send me a test</button>
  <button class="quiet" onclick="remove()">stop everything</button>
</div>
<p><small>Device notifications work on Chrome, Edge, Firefox, Chromebooks and
Android directly — if the browser offers to &ldquo;Add to Home screen&rdquo;,
that&rsquo;s optional there. On iPhone/iPad it is required: share &rarr; Add
to Home Screen, then open from there (iOS only pushes to installed pages).
The engine never asks you for anything by email.</small></p>
<pre id="out">ready.</pre>
<script>
var out = document.getElementById('out');
function say(x) {
  if (typeof x === 'string') { out.textContent = x; return; }
  if (x && typeof x === 'object' && (x.detail || x.sent)) {
    var line = (x.ok === false ? '✗ ' : '✓ ') + (x.detail || '');
    if (Array.isArray(x.sent)) {
      var names = x.sent.map(function (s) { return s === 'webpush' ? 'this device' : s; });
      line += names.length ? ('\nsent via: ' + names.join(' + '))
                           : '\nnothing was sent — no channel is switched on yet.';
    }
    out.textContent = line;
    return;
  }
  out.textContent = JSON.stringify(x, null, 2);
}
function ident() { return { handle: document.getElementById('h').value.trim(),
                            passphrase: document.getElementById('p').value }; }
function post(path, body, method) {
  return fetch(path, { method: method || 'POST',
    headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })
    .then(function (r) { return r.json(); }).then(say)
    .catch(function (e) { say('failed: ' + e); });
}
function enrol() {
  var b = ident();
  b.email = document.getElementById('email').value.trim();
  b.ntfy = document.getElementById('ntfy').value.trim();
  post('/enroll', b);
}
function remove() { post('/enroll', ident(), 'DELETE'); }
function test() { post('/test', ident()); }
function b64ToU8(s) {
  var pad = '='.repeat((4 - s.length % 4) % 4);
  var raw = atob((s + pad).replace(/-/g, '+').replace(/_/g, '/'));
  return Uint8Array.from(raw, function (c) { return c.charCodeAt(0); });
}
async function push() {
  try {
    if (!('serviceWorker' in navigator) || !('PushManager' in window)) {
      return say('this browser has no web push (on iOS: Add to Home Screen first).');
    }
    var v = await (await fetch('/vapid')).json();
    if (!v.publicKey) return say('the engine has no VAPID keys yet.');
    var reg = await navigator.serviceWorker.register('/sw.js');
    var perm = await Notification.requestPermission();
    if (perm !== 'granted') return say('notification permission was ' + perm + '.');
    var sub = await reg.pushManager.subscribe({
      userVisibleOnly: true, applicationServerKey: b64ToU8(v.publicKey) });
    var b = ident(); b.webpush = sub.toJSON();
    await post('/enroll', b);
  } catch (e) { say('push setup failed: ' + e); }
}
</script>
"""

PUBLIC_URL = os.environ.get("PUBLIC_URL", "").rstrip("/")

# Browser doors (the mirror's holder pane, xstream) call /enroll, /test and
# /vapid directly — same posture as the waker's CORS (its d4b4f72): a short
# allowlist, credentials never involved, the beach never carries a secret.
CORS_ORIGINS = [o.strip() for o in os.environ.get(
    "ENGINE_CORS_ORIGINS",
    "https://mirror.onen.ai,https://xstream.onen.ai,http://localhost:5173"
).split(",") if o.strip()]


# ── the wire ────────────────────────────────────────────────────────────────

class Handler(BaseHTTPRequestHandler):
    def _cors(self):
        origin = self.headers.get("origin", "")
        if origin in CORS_ORIGINS:
            self.send_header("access-control-allow-origin", origin)
            self.send_header("access-control-allow-methods",
                             "GET, POST, DELETE, OPTIONS")
            self.send_header("access-control-allow-headers", "content-type")

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.send_header("content-length", "0")
        self.end_headers()

    def _send(self, code, obj, ctype="application/json"):
        body = obj if isinstance(obj, bytes) else \
            (obj.encode() if isinstance(obj, str) else json.dumps(obj).encode())
        self.send_response(code)
        self.send_header("content-type", ctype)
        self.send_header("content-length", str(len(body)))
        self._cors()
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass

    def _body_raw(self):
        length = int(self.headers.get("content-length", "0"))
        return self.rfile.read(length)

    def do_GET(self):
        path = self.path.split("?")[0].rstrip("/")
        if path in ("", "/health"):
            self._send(200, {
                "ok": True, "service": "push-engine (the beach reaches people)",
                "boot": BOOT_TS, "beach": BEACH, "enrolled": len(_store_load()),
                "channels": {"email": bool(GMAIL_ADDRESS and GMAIL_APP_PASSWORD),
                             "ntfy": True, "webpush": WEBPUSH_READY},
                "fanout": len(FANOUT_URLS),
                "law": "subscriptions are public blocks (ear:<handle>); "
                       "channels live here by proof; ways:push at the beach"})
        elif path == "/vapid":
            self._send(200, {"publicKey": VAPID_PUBLIC})
        elif path == "/push":
            self._send(200, PUSH_PAGE, "text/html; charset=utf-8")
        elif path == "/sw.js":
            self._send(200, SW_JS, "application/javascript")
        elif path == "/manifest.json":
            self._send(200, MANIFEST, "application/manifest+json")
        elif path == "/icon.png":
            self._send(200, _ICON, "image/png")
        else:
            self._send(404, {"error": "not found"})

    def _enroll(self, remove):
        try:
            b = json.loads(self._body_raw().decode() or "{}")
        except Exception:
            return self._send(400, {"ok": False, "detail": "unparseable body"})
        handle = str(b.get("handle", "")).strip()
        passphrase = str(b.get("passphrase", ""))
        if not handle or not passphrase:
            return self._send(400, {"ok": False,
                                    "detail": "handle and passphrase are both needed"})
        if _throttled(handle):
            return self._send(429, {"ok": False,
                                    "detail": "too many failed proofs for this handle — wait an hour"})
        ok, reason = prove_or_found(handle, passphrase)
        log("enrolment %s for %s: %s (%s)"
            % ("remove" if remove else "add", handle,
               "proven" if ok else "REFUSED", reason))
        if not ok:
            return self._send(403, {"ok": False, "detail": reason})
        with _store_lock:
            store = _store_load()
            if remove:
                if handle in store:
                    del store[handle]
                    _store_save(store)
                return self._send(200, {"ok": True,
                                        "detail": "%s removed — nothing reaches you from here any more" % handle})
            e = store.get(handle, {})
            for k in ("email", "ntfy"):
                if k in b:  # present-and-empty clears that channel
                    v = str(b.get(k, "")).strip()
                    if v:
                        e[k] = v
                    else:
                        e.pop(k, None)
            wp = b.get("webpush")
            if isinstance(wp, dict) and wp.get("endpoint"):
                subs = [s for s in e.get("webpush", [])
                        if s.get("endpoint") != wp["endpoint"]]
                subs.append(wp)
                e["webpush"] = subs
            e["ts"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            store[handle] = e
            _store_save(store)
        chans = [k for k in ("email", "ntfy", "webpush") if e.get(k)]
        return self._send(200, {"ok": True, "proof": reason,
                                "detail": "%s hears by %s — what you hear about is ear:%s, yours to edit"
                                % (handle, ", ".join(chans) or "no channel yet", handle)})

    def _test(self):
        try:
            b = json.loads(self._body_raw().decode() or "{}")
        except Exception:
            return self._send(400, {"ok": False, "detail": "unparseable body"})
        handle = str(b.get("handle", "")).strip()
        passphrase = str(b.get("passphrase", ""))
        if not handle or not passphrase:
            return self._send(400, {"ok": False,
                                    "detail": "handle and passphrase are both needed"})
        if _throttled(handle):
            return self._send(429, {"ok": False, "detail": "too many failed proofs — wait an hour"})
        ok, reason = prove_or_found(handle, passphrase)
        if not ok:
            return self._send(403, {"ok": False, "detail": reason})
        sent = deliver(handle, {"email", "ntfy", "webpush"},
                       "the beach can reach you",
                       "This is the test you asked for — the engine heard you ask, and this is what a note feels like.",
                       (PUBLIC_URL or "") + "/push", test=True)
        log("test for %s: sent via %s" % (handle, ",".join(sent) or "nothing"))
        return self._send(200, {"ok": True, "sent": sent or [],
                                "detail": ("test sent via %s" % ", ".join(sent))
                                if sent else "no channel is enrolled (or none is configured server-side)"})

    def do_POST(self):
        path = self.path.split("?")[0].rstrip("/")
        if path == "/enroll":
            return self._enroll(remove=False)
        if path == "/test":
            return self._test()
        if path != "/event":
            return self._send(404, {"error": "not found"})
        got = self.headers.get("x-pool-webhook-secret", "")
        if not ENGINE_SECRET or not hmac.compare_digest(got, ENGINE_SECRET):
            log("event refused: %s" % ("no shared-secret header" if not got
                                       else "mismatched shared secret"))
            return self._send(403, {"error": "bad shared secret"})
        raw = self._body_raw()
        try:
            payload = json.loads(raw.decode() or "{}")
        except Exception:
            return self._send(400, {"error": "unparseable body"})
        origin = str(payload.get("origin", ""))
        pool = str(payload.get("pool", ""))
        slot = str(payload.get("slot", ""))
        if origin and host_of(origin) != host_of(BEACH):
            log("event ignored: origin %s is not the pinned beach" % origin)
            return self._send(200, {"ok": True, "ignored": "foreign origin"})
        key = "%s|%s|%s" % (origin, pool, slot) if (pool and slot) \
            else base64.b64encode(raw[:256]).decode()
        if seen_before(key):
            return self._send(200, {"ok": True, "dedup": True})
        log("event: %s slot %s by %s" % (pool or "(no pool)", slot or "-",
                                         payload.get("agent_id") or "anon"))
        fanout(raw)  # the bus duty first — downstream sees the beach's bytes
        if pool.startswith("pool:"):
            event = {"origin": origin, "pool": pool, "slot": slot,
                     "agent_id": str(payload.get("agent_id", "") or ""),
                     "ts": str(payload.get("ts", "") or "")}
            threading.Thread(target=match_and_deliver, args=(event,),
                             daemon=True).start()
        self._send(200, {"ok": True})

    def do_DELETE(self):
        if self.path.split("?")[0].rstrip("/") == "/enroll":
            return self._enroll(remove=True)
        self._send(404, {"error": "not found"})


def main():
    if not ENGINE_SECRET:
        log("WARNING: ENGINE_SECRET unset — every event will be refused")
    if not (GMAIL_ADDRESS and GMAIL_APP_PASSWORD):
        log("email channel dark: sender credentials unset")
    if not WEBPUSH_READY:
        log("webpush channel dark: %s" % ("pywebpush not installed"
                                          if not webpush else "VAPID keys unset"))
    port = int(os.environ.get("PORT", "8080"))
    log("listening on :%d — beach %s, fanout %s, enrolled %d"
        % (port, BEACH, FANOUT_URLS or "none", len(_store_load())))
    ThreadingHTTPServer(("", port), Handler).serve_forever()


if __name__ == "__main__":
    main()
