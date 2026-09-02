# Guardian Angel 🛡️

Network-level site blocking for macOS that survives a different browser, a
deleted app, a reboot, and you, at 11pm, with sudo.

Full spec (architecture, diagrams, threat model):
https://claude.ai/code/artifact/0c648624-b3b7-4af4-aae0-6dc8e8f37b84

## How it works

- Blocked domains sinkhole to `0.0.0.0` via a marked section of `/etc/hosts` —
  covers every app, not one browser.
- A PF firewall anchor closes the encrypted-DNS side door (DoT :853, DoH to
  known resolver IPs, with `block return` so browsers fall back instantly).
- `guardiand`, a root launchd daemon with `KeepAlive`, sleeps on a kqueue
  watch and reverts any tampering with the hosts file or its own plist in
  milliseconds. PF is re-checked on a 60s fallback timer.
- Loosening anything requires a **one-time code held by a friend** (only
  salted SHA-256 hashes live on disk; codes burn on use).
- The escape hatch never needs a code: `guardian emergency` disarms
  **24 hours later**, cancelable anytime before.

Tightening is free. Loosening costs a code. Escaping costs a day.

## Install

```sh
./guardian.py install     # copies to /usr/local, starts the daemon (asks for sudo)
guardian init             # prints your 20 one-time codes — ONCE
# → text the codes to your friend, delete your copy
guardian add reddit.com
guardian arm
```

## Daily driving

```sh
guardian status           # state, blocklist, codes remaining
guardian add news.ycombinator.com     # free — tightening never needs auth
guardian pause 30m        # costs one code, auto re-arms
guardian remove <domain>  # costs one code
guardian disarm           # costs one code
guardian emergency        # free — disarm lands in 24h; `emergency cancel` anytime
guardian regen            # rotate the code batch (costs a code while armed)
guardian uninstall        # only from DISARMED
```

## Honesty

This is friction engineering, not security. You have root; you can always win
eventually (the spec's threat ledger prices every bypass). The design's only
promise is that "eventually" is longer than an urge.

## Development

`GUARDIAN_PREFIX=/some/dir` redirects every system path (hosts, pf.conf,
LaunchDaemons, state) under that directory and skips `pfctl`/`launchctl`/sudo,
so the whole state machine is testable without touching the real system:

```sh
mkdir -p /tmp/fake/etc && touch /tmp/fake/etc/hosts
GUARDIAN_PREFIX=/tmp/fake ./guardian.py init
GUARDIAN_PREFIX=/tmp/fake ./guardian.py daemon --once
```
