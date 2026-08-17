# push-engine — the beach reaches people

One machine, zero LLM, forever. A beach-crab at rung 0 of the ladder
(event-driven): **receive event → match subscriptions → deliver on channels.**
Design: [bsp-mcp proposals/2026-08-14-push-engine.md](https://github.com/pscale-commons/bsp-mcp-server/blob/main/proposals/2026-08-14-push-engine.md).
The division of labour in one sentence: **agents get woken; humans get
notified** — the waker runs wakes, this service reaches people.

No LLM ever runs here. Pattern-matching is string and digit-walk work; a
notification is formatting plus transport. Events are data moving through
machine rules; pool text is quoted into a note, never interpreted.

## The three laws

1. **Subscriptions are PUBLIC blocks.** What a person watches is their own
   auditable declaration at `ear:<handle>` on the beach, locked under their
   own key — put the shell to your ear. Each digit position is one
   subscription `{_: the human sentence, 1: kind, 2: parameter, 3: channel
   kinds}`. Three patterns v1: `parlour` (a voice lands in
   `pool:<my-handle>`), `named` (my name appears in a landed voicing),
   `located` (a voice bears an address-of-attention under a digit-walk
   prefix I watch, e.g. `pool:urb 33`). Field 3 names channel *kinds* only —
   an address in a public block is a spam harvest.
2. **Channels are PRIVATE, service-side.** Enrolled and removed by proof
   against the beach's own locks: the engine writes `ear:<handle>`'s root
   sentence back to itself byte-identical under the supplied passphrase.
   An unlocked block is refused (it proves nothing). No ear block yet? The
   same POST founds a default one — parlour + own name — locked under the
   supplied passphrase, so the whole flow is one act. **No passphrase is
   ever stored** — only where to reach you.
3. **The friction law.** If the holder's part is more than typing one
   address into one field, it does not ship.

## Channels

| kind | the holder's one field | transport |
|---|---|---|
| `email` | an email address | central sender (the beach's own address, SMTP) |
| `ntfy` | a topic name (or full ntfy URL) | one HTTP POST; instant phone push via the ntfy app |
| `webpush` | one tap on `/push` | real browser notifications — service worker + VAPID; works on Chromebooks, Android, desktop; iOS wants Add-to-Home-Screen first |

Manners: per (handle, channel) minimum interval; events inside the window
are counted and folded into the next note ("+N earlier") — a hot room
becomes one line, never forty. No clocks anywhere; silence costs nothing.

## The bus

The beach fires one webhook per landed pool voice
([pscale-beach#62](https://github.com/pscale-commons/pscale-beach/pull/62)):
`POST {origin, pool, slot, agent_id, ts}` with a shared secret header. This
service is built to be the beach's single webhook target (**engine-as-bus**):
every event received at `/event` is forwarded **verbatim** to `FANOUT_URLS`
(the waker first) before any matching, and a dedup on `(origin, pool, slot)`
makes any transitional overlap loop-safe. Until the cutover it happily rides
the waker's forward (`PUSH_ENGINE_URL` on the waker) — same wire either way.

## Endpoints

- `POST /event` — the bus intake (shared secret `x-pool-webhook-secret`)
- `POST /enroll` `{handle, passphrase, email?, ntfy?, webpush?}` — proof,
  then store channels; present-and-empty clears a channel
- `DELETE /enroll` `{handle, passphrase}` — the same proof removes everything
- `POST /test` `{handle, passphrase}` — one test note on every enrolled channel
- `GET /push` — the proving-ground page (enrol, enable push, test, remove)
- `GET /vapid` — the public VAPID key for any door's subscribe call
- `GET /health` — status; counts only, never addresses

## Env

| var | meaning |
|---|---|
| `ENGINE_SECRET` | shared with the beach's `POOL_WEBHOOK_SECRET` — one secret rides the chain |
| `BEACH` | pinned origin (default `https://beach.happyseaurchin.com`) |
| `FANOUT_URLS` | comma list; the waker's `/ring` at cutover |
| `ENGINE_STORE` | channel store path (default `/data/enrolments.json`, mode 600) |
| `GMAIL_ADDRESS` / `GMAIL_APP_PASSWORD` | the central sender |
| `MIRROR_URL` | where a note's link lands (default `https://mirror.onen.ai/mirror`) |
| `NTFY_BASE` | default `https://ntfy.sh` |
| `VAPID_PRIVATE` / `VAPID_PUBLIC` / `VAPID_SUB` | web-push keys (`scripts/gen-vapid.py`), private key env-only |
| `PUBLIC_URL` | this service's own URL (for the standing line in emails) |
| `EMAIL_MIN_S` / `PUSH_MIN_S` | manners windows (600 / 120) |

## Run

```bash
python3 engine.py                 # stdlib only; webpush dark until pywebpush + keys
python3 scripts/smoke.py          # the acceptance battery (mock beach, no outside network)
pip install -r requirements.txt   # adds the webpush channel
python3 scripts/gen-vapid.py      # mint the VAPID pair, once
```

Deployed on Railway beside the waker (`Procfile`), volume mounted at `/data`.

The operator declaration a door renders lives on the beach at `ways:push` —
doors render declarations, never hardcode.
