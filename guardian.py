#!/usr/bin/env python3
"""Guardian Angel — network-level site blocking that survives sudo, reboots, and 11pm-you.

One file, stdlib only. Acts as both the CLI (`guardian <cmd>`) and the
daemon (`guardian daemon`, run by launchd as root).

Spec: https://claude.ai/code/artifact/0c648624-b3b7-4af4-aae0-6dc8e8f37b84
"""

import hashlib
import json
import os
import plistlib
import re
import secrets
import select
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time

# ---------------------------------------------------------------- paths

PREFIX = os.environ.get("GUARDIAN_PREFIX", "")
TESTING = bool(PREFIX) or os.environ.get("GUARDIAN_TESTING") == "1"

INSTALL_DIR = PREFIX + "/usr/local/guardian-angel"
APP_DIR = PREFIX + "/Library/Application Support/GuardianAngel"
HOSTS = PREFIX + "/etc/hosts"
PF_CONF = PREFIX + "/etc/pf.conf"
LAUNCHD_DIR = PREFIX + "/Library/LaunchDaemons"
LABEL = "com.guardian-angel.daemon"
PLIST = os.path.join(LAUNCHD_DIR, LABEL + ".plist")
CANONICAL_PLIST = os.path.join(INSTALL_DIR, "daemon.plist")
PF_RULES = os.path.join(INSTALL_DIR, "pf.rules")
BIN_LINK = PREFIX + "/usr/local/bin/guardian"
LOG = PREFIX + "/var/log/guardian-angel.log"

CONFIG = os.path.join(APP_DIR, "config.json")
CODES = os.path.join(APP_DIR, "codes.json")
STATE = os.path.join(APP_DIR, "state.json")

MARK_BEGIN = "# >>> guardian-angel — do not edit, it will be rewritten >>>"
MARK_END = "# <<< guardian-angel <<<"

SUBDOMAINS = ["", "www.", "m.", "old.", "new.", "amp.", "i.", "api."]

# No 0/O, 1/I/L, 5/S, 8/B — codes get read out loud over the phone.
ALPHABET = "ACDEFGHJKMNPQRTUVWXYZ234679"
BATCH_SIZE = 20
FAIL_LOCKOUT_SECS = 30

PF_RULES_TEXT = """\
# guardian-angel — loaded into anchor "guardian-angel"
# Closes the encrypted-DNS side door. Plain port-53 DNS stays open:
# the system resolver honors /etc/hosts before any server is asked.
table <doh> { 1.1.1.1, 1.0.0.1, 8.8.8.8, 8.8.4.4, 9.9.9.9, \\
              149.112.112.112, 208.67.222.222, 208.67.220.220, \\
              94.140.14.14, 94.140.15.15 }
# "return", not "drop": an instant RST makes browsers fall back to the
# system resolver immediately instead of hanging on a timeout.
block return out quick proto { tcp udp } to any port 853
block return out quick proto tcp to <doh> port 443
"""

FAMILY_DNS = ["1.1.1.3", "1.0.0.3", "2606:4700:4700::1113", "2606:4700:4700::1003"]

# The service door: a localhost CONNECT proxy run by the daemon. It resolves
# names itself (sidestepping the /etc/hosts sinkhole) and tunnels anywhere —
# scrapers and CLI tools opt in via HTTPS_PROXY, while browsers stay on the
# system resolver and hit the wall (and the door turns Mozillas away).
# Nobody doomscrolls through curl; the ledger prices the rest.
PROXY_PORT = 8118

# Appended to pf.rules while the nsfw filter is on. The DNS pin in System
# Settings makes name resolution *work*; these rules make it *mandatory* —
# pointing DNS anywhere else fails closed instead of bypassing the filter.
FILTER_RULES_TEXT = """\
table <familydns> { %s }
pass out quick proto { tcp udp } to <familydns> port 53
block return out quick proto { tcp udp } to any port 53
""" % ", ".join(FAMILY_DNS)


def pf_rules_text(filter_on):
    return PF_RULES_TEXT + (FILTER_RULES_TEXT if filter_on else "")


PF_ANCHOR_LINES = [
    'anchor "guardian-angel"',
    'load anchor "guardian-angel" from "%s"' % (PREFIX + "/usr/local/guardian-angel/pf.rules"),
]

# ---------------------------------------------------------------- helpers


def log(msg):
    line = "%s %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), msg)
    print(line, flush=True)


def die(msg, code=1):
    print("guardian: %s" % msg, file=sys.stderr)
    sys.exit(code)


def run(cmd, check=False):
    """Run a system command; no-op in test mode."""
    if TESTING:
        log("[test] skip: %s" % " ".join(cmd))
        return 0
    try:
        r = subprocess.run(cmd, capture_output=True, text=True)
        if check and r.returncode != 0:
            log("cmd failed (%s): %s" % (" ".join(cmd), r.stderr.strip()))
        return r.returncode
    except FileNotFoundError:
        log("cmd not found: %s" % cmd[0])
        return 127


def need_root():
    """Mutating commands re-exec themselves under sudo."""
    if TESTING or os.geteuid() == 0:
        return
    os.execvp("sudo", ["sudo", sys.executable, os.path.abspath(__file__)] + sys.argv[1:])


def load_json(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return dict(default)


def save_json(path, data, mode=0o644):
    # Root-owned either way; 0644 lets unprivileged `status` read. Only
    # codes.json (crackable-offline hashes) needs 0600.
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


DEFAULT_CONFIG = {"domains": [], "emergency_delay_hours": 24, "filter": False}
DEFAULT_STATE = {"armed": False, "pause_until": None, "emergency_at": None, "last_fail": 0}


def load_all():
    return (
        load_json(CONFIG, DEFAULT_CONFIG),
        load_json(STATE, DEFAULT_STATE),
    )


# ---------------------------------------------------------------- codes


def gen_code():
    grp = lambda: "".join(secrets.choice(ALPHABET) for _ in range(4))
    return "GA-%s-%s" % (grp(), grp())


def normalize(code):
    c = re.sub(r"[^A-Za-z0-9]", "", code).upper()
    return c[2:] if c.startswith("GA") else c


def hash_code(salt, code):
    return hashlib.sha256((salt + normalize(code)).encode()).hexdigest()


def gen_batch():
    plain, stored = [], []
    for _ in range(BATCH_SIZE):
        code = gen_code()
        salt = secrets.token_hex(16)
        plain.append(code)
        stored.append({"salt": salt, "hash": hash_code(salt, code), "used": False})
    save_json(CODES, {"codes": stored}, mode=0o600)
    return plain


def codes_remaining():
    """Unused-code count, or None when codes.json isn't readable (no sudo)."""
    try:
        data = load_json(CODES, {"codes": []})
    except PermissionError:
        return None
    return sum(1 for c in data["codes"] if not c["used"])


def verify_and_burn(code):
    """True if code is valid and unused; burns it. Rate-limited on failure."""
    state = load_json(STATE, DEFAULT_STATE)
    wait = state.get("last_fail", 0) + FAIL_LOCKOUT_SECS - time.time()
    if wait > 0:
        die("wrong code recently — wait %ds and try again" % int(wait))
    data = load_json(CODES, {"codes": []})
    for entry in data["codes"]:
        if not entry["used"] and entry["hash"] == hash_code(entry["salt"], code):
            entry["used"] = True
            save_json(CODES, data, mode=0o600)
            return True
    state["last_fail"] = time.time()
    save_json(STATE, state)
    return False


def require_code(action):
    if codes_remaining() == 0:
        die("no unused codes left. Escape hatch: `guardian emergency` (24h delay), "
            "then regenerate a batch while disarmed.")
    code = input("One-time code to %s (ask your friend): " % action).strip()
    if not verify_and_burn(code):
        die("invalid or already-used code")
    left = codes_remaining()
    print("Code accepted and burned. %d remaining." % left)
    if left < 5:
        print("⚠ Running low — regenerate a batch soon (`guardian regen`).")


# ---------------------------------------------------------------- state machine


def emergency_deadline(config, state):
    if state.get("emergency_at") is None:
        return None
    return state["emergency_at"] + config.get("emergency_delay_hours", 24) * 3600


def settle(config, state, persist=True):
    """Apply timer expiries. persist=False mutates in memory only (for
    unprivileged `status`; the daemon persists on its next wake)."""
    now = time.time()
    changed = False
    dl = emergency_deadline(config, state)
    if dl is not None and now >= dl:
        state["armed"] = False
        state["emergency_at"] = None
        changed = True
        if persist:
            log("emergency cooling-off elapsed → DISARMED")
    if state.get("pause_until") and now >= state["pause_until"]:
        state["pause_until"] = None
        changed = True
        if persist:
            log("pause expired → re-armed")
    if changed and persist:
        save_json(STATE, state)
    return changed


def is_active(state):
    if not state.get("armed"):
        return False
    if state.get("pause_until") and time.time() < state["pause_until"]:
        return False
    return True


# ---------------------------------------------------------------- enforcement


def block_lines(domains):
    lines = [MARK_BEGIN]
    for d in sorted(domains):
        hosts = " ".join(s + d for s in SUBDOMAINS)
        lines.append("0.0.0.0 " + hosts)
        lines.append(":: " + hosts)
    lines.append(MARK_END)
    return lines


def read_hosts():
    try:
        with open(HOSTS) as f:
            return f.read()
    except FileNotFoundError:
        return ""


def split_hosts(text):
    """Return (rest_of_file, current_guardian_section_lines_or_None)."""
    lines = text.splitlines()
    if MARK_BEGIN not in lines:
        return text.rstrip("\n"), None
    i, j = lines.index(MARK_BEGIN), None
    for k in range(i, len(lines)):
        if lines[k] == MARK_END:
            j = k
            break
    if j is None:  # truncated tampering — treat everything after BEGIN as ours
        j = len(lines) - 1
    rest = lines[:i] + lines[j + 1:]
    return "\n".join(rest).rstrip("\n"), lines[i:j + 1]


def write_hosts(rest, section):
    body = rest.rstrip("\n")
    if section:
        body += "\n\n" + "\n".join(section)
    body += "\n"
    tmp = HOSTS + ".guardian.tmp"
    with open(tmp, "w") as f:
        f.write(body)
    os.chmod(tmp, 0o644)
    os.replace(tmp, HOSTS)


def flush_dns():
    run(["dscacheutil", "-flushcache"])
    run(["killall", "-HUP", "mDNSResponder"])


def ensure_hosts(domains, active):
    """Make /etc/hosts match desired state. Returns True if it changed."""
    rest, current = split_hosts(read_hosts())
    desired = block_lines(domains) if (active and domains) else None
    if current == desired:
        return False
    write_hosts(rest, desired)
    flush_dns()
    log("hosts %s" % ("rewritten" if desired else "section removed"))
    return True


def ensure_pf(active, filter_on=False):
    if TESTING:
        return
    desired = pf_rules_text(filter_on)
    try:
        with open(PF_RULES) as f:
            on_disk = f.read()
    except FileNotFoundError:
        on_disk = ""
    rules_changed = on_disk != desired
    if rules_changed:
        os.makedirs(INSTALL_DIR, exist_ok=True)
        with open(PF_RULES, "w") as f:
            f.write(desired)
    try:
        with open(PF_CONF) as f:
            conf = f.read()
    except FileNotFoundError:
        conf = ""
    missing = [l for l in PF_ANCHOR_LINES if l not in conf]
    if active and missing:
        with open(PF_CONF, "a") as f:
            f.write("\n" + "\n".join(missing) + "\n")
        run(["pfctl", "-f", PF_CONF])
        log("pf.conf anchor lines restored")
    if active:
        run(["pfctl", "-E"])
        # anchor empty (flushed by hand) or rules stale? reload it
        r = subprocess.run(["pfctl", "-a", "guardian-angel", "-sr"],
                           capture_output=True, text=True)
        if rules_changed or not r.stdout.strip():
            run(["pfctl", "-a", "guardian-angel", "-f", PF_RULES])
            log("pf anchor reloaded (filter %s)" % ("on" if filter_on else "off"))
    else:
        run(["pfctl", "-a", "guardian-angel", "-F", "rules"])


def network_services():
    r = subprocess.run(["networksetup", "-listallnetworkservices"],
                       capture_output=True, text=True)
    # first line is a legend; a leading "*" marks a disabled service
    return [l.lstrip("*").strip() for l in r.stdout.splitlines()[1:] if l.strip()]


def ensure_dns_pin(pin):
    """Pin every network service's DNS to Cloudflare Family, or release a
    pin that is ours. Never clobbers DNS servers we didn't set."""
    if TESTING:
        return
    for svc in network_services():
        r = subprocess.run(["networksetup", "-getdnsservers", svc],
                           capture_output=True, text=True)
        current = [l.strip() for l in r.stdout.splitlines() if l.strip()]
        if pin and current != FAMILY_DNS:
            run(["networksetup", "-setdnsservers", svc] + FAMILY_DNS)
            log("dns pinned to Cloudflare Family (%s)" % svc)
        elif not pin and current == FAMILY_DNS:
            run(["networksetup", "-setdnsservers", svc, "Empty"])
            log("dns pin released (%s)" % svc)


def ensure_no_sys_proxy(active):
    """Browsers honor the *system* proxy — don't let one be pointed at our
    own service door."""
    if TESTING or not active:
        return
    for svc in network_services():
        for get_cmd, set_cmd in (("-getwebproxy", "-setwebproxystate"),
                                 ("-getsecurewebproxy", "-setsecurewebproxystate")):
            r = subprocess.run(["networksetup", get_cmd, svc],
                               capture_output=True, text=True)
            out = r.stdout
            if ("Enabled: Yes" in out and "127.0.0.1" in out
                    and str(PROXY_PORT) in out):
                run(["networksetup", set_cmd, svc, "off"])
                log("system proxy aimed at the service door — cleared (%s)" % svc)


def ensure_plist():
    """Restore our launchd plist from the canonical copy if tampered with."""
    if not os.path.exists(CANONICAL_PLIST):
        return
    try:
        with open(PLIST, "rb") as f:
            current = f.read()
    except FileNotFoundError:
        current = b""
    with open(CANONICAL_PLIST, "rb") as f:
        canonical = f.read()
    if current != canonical:
        shutil.copyfile(CANONICAL_PLIST, PLIST)
        os.chmod(PLIST, 0o644)
        run(["launchctl", "enable", "system/" + LABEL])
        log("launchd plist restored")


def enforce_once():
    config, state = load_all()
    settle(config, state)
    active = is_active(state)
    filtering = active and config.get("filter", False)
    ensure_hosts(config["domains"], active)
    ensure_pf(active, filtering)
    ensure_dns_pin(filtering)
    ensure_no_sys_proxy(active)
    ensure_plist()
    return config, state


# ---------------------------------------------------------------- service door


def _skip_name(data, i):
    while i < len(data):
        b = data[i]
        if b == 0:
            return i + 1
        if b & 0xC0:  # compression pointer
            return i + 2
        i += b + 1
    return i


def dns_resolve(host, server):
    """Minimal A-record lookup straight to `server`, bypassing the system
    resolver — and therefore the /etc/hosts sinkhole. Plain port 53, which
    our own PF rules always leave open to the resolver in use."""
    tid = secrets.randbelow(65536)
    q = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    for part in host.split("."):
        q += bytes([len(part)]) + part.encode()
    q += b"\x00" + struct.pack(">HH", 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.settimeout(3)
        s.sendto(q, (server, 53))
        data, _ = s.recvfrom(2048)
    except OSError:
        return []
    finally:
        s.close()
    if len(data) < 12 or data[:2] != q[:2]:
        return []
    ancount = struct.unpack(">H", data[6:8])[0]
    i = _skip_name(data, 12) + 4  # question: name + qtype + qclass
    addrs = []
    for _ in range(ancount):
        i = _skip_name(data, i)
        if i + 10 > len(data):
            break
        rtype, _, _, rdlen = struct.unpack(">HHIH", data[i:i + 10])
        i += 10
        if rtype == 1 and rdlen == 4:
            addrs.append(".".join(str(b) for b in data[i:i + 4]))
        i += rdlen
    return addrs


def _refuse(conn, status, msg):
    body = msg + "\n"
    conn.sendall(("HTTP/1.1 %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s"
                  % (status, len(body), body)).encode())


def _pipe(src, dst):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        for s in (src, dst):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def proxy_handle(conn):
    up = None
    try:
        conn.settimeout(15)
        req = b""
        while b"\r\n\r\n" not in req and len(req) < 8192:
            chunk = conn.recv(4096)
            if not chunk:
                return
            req += chunk
        head, _, extra = req.partition(b"\r\n\r\n")
        head = head.decode("latin1", "replace")
        parts = head.split("\r\n", 1)[0].split()
        if len(parts) != 3 or parts[0] != "CONNECT":
            _refuse(conn, "405 Method Not Allowed", "guardian door: CONNECT (https) only")
            return
        # Browsers announce themselves in CONNECT headers; the door is for
        # CLI tools. Spoofable on purpose — see the threat ledger.
        if re.search(r"^user-agent:.*mozilla", head, re.I | re.M):
            _refuse(conn, "403 Forbidden", "guardian door: browsers keep hitting the wall")
            return
        host, sep, port = parts[1].rpartition(":")
        if not sep:
            host, port = parts[1], "443"
        try:
            port = int(port)
        except ValueError:
            _refuse(conn, "400 Bad Request", "guardian door: bad CONNECT target")
            return
        host = host.strip("[]").lower().rstrip(".")
        config, state = load_all()
        if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", host):
            addrs = [host]
        else:
            # With the nsfw filter on, the door resolves through Cloudflare
            # Family too — it can't reach what the filter wouldn't. The
            # fallback covers a config/PF mismatch mid-toggle; when the
            # filter's PF rules are up, only the family resolver is
            # reachable anyway, so this can't relax the filter.
            filtering = is_active(state) and config.get("filter")
            order = [FAMILY_DNS[0], "1.1.1.1"] if filtering else ["1.1.1.1", FAMILY_DNS[0]]
            addrs = dns_resolve(host, order[0]) or dns_resolve(host, order[1])
        if not addrs or addrs[0] == "0.0.0.0":
            _refuse(conn, "502 Bad Gateway", "guardian door: could not resolve %s" % host)
            return
        try:
            up = socket.create_connection((addrs[0], port), timeout=10)
        except OSError as e:
            _refuse(conn, "502 Bad Gateway", "guardian door: connect failed (%s)" % e)
            return
        conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        if extra:
            up.sendall(extra)
        conn.settimeout(None)
        up.settimeout(None)
        t = threading.Thread(target=_pipe, args=(conn, up), daemon=True)
        t.start()
        _pipe(up, conn)
        t.join(timeout=5)
    except OSError:
        pass
    finally:
        for s in (conn, up):
            if s is not None:
                try:
                    s.close()
                except OSError:
                    pass


def proxy_serve():
    try:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", PROXY_PORT))
        srv.listen(16)
    except OSError as e:
        log("service door failed to bind 127.0.0.1:%d (%s)" % (PROXY_PORT, e))
        return
    log("service door listening on 127.0.0.1:%d" % PROXY_PORT)
    while True:
        try:
            conn, _ = srv.accept()
        except OSError:
            continue
        threading.Thread(target=proxy_handle, args=(conn,), daemon=True).start()


# ---------------------------------------------------------------- daemon


def next_deadline(config, state):
    now = time.time()
    candidates = []
    if state.get("pause_until") and state["pause_until"] > now:
        candidates.append(state["pause_until"])
    dl = emergency_deadline(config, state)
    if dl is not None and dl > now:
        candidates.append(dl)
    return min(candidates) if candidates else None


def kqueue_wait(timeout):
    """Block until /etc/hosts or the LaunchDaemons dir changes, or timeout."""
    fds = []
    try:
        kq = select.kqueue()
        events = []
        for path in (HOSTS, LAUNCHD_DIR):
            try:
                fd = os.open(path, os.O_RDONLY)
                fds.append(fd)
                events.append(select.kevent(
                    fd,
                    filter=select.KQ_FILTER_VNODE,
                    flags=select.KQ_EV_ADD | select.KQ_EV_CLEAR,
                    fflags=(select.KQ_NOTE_WRITE | select.KQ_NOTE_DELETE |
                            select.KQ_NOTE_RENAME | select.KQ_NOTE_EXTEND),
                ))
            except OSError:
                pass
        if events:
            kq.control(events, 0, 0)
        kq.control(None, 4, timeout)
        kq.close()
    except OSError:
        time.sleep(min(timeout, 5))
    finally:
        for fd in fds:
            try:
                os.close(fd)
            except OSError:
                pass


def cmd_daemon(args):
    once = "--once" in args
    log("guardiand starting (pid %d)%s" % (os.getpid(), " [test]" if TESTING else ""))
    if not once:
        threading.Thread(target=proxy_serve, daemon=True).start()
    while True:
        config, state = enforce_once()
        if once:
            return
        deadline = next_deadline(config, state)
        timeout = 60.0
        if deadline is not None:
            timeout = max(1.0, min(timeout, deadline - time.time() + 1))
        # Watched fds go stale after our own atomic replace of /etc/hosts,
        # so watches are re-opened fresh on every wait.
        kqueue_wait(timeout)


# ---------------------------------------------------------------- CLI commands


def fmt_ts(ts):
    return time.strftime("%a %H:%M", time.localtime(ts))


def cmd_status(args):
    try:
        config, state = load_all()
    except PermissionError:
        die("state files aren't readable — re-run `./guardian.py install` once "
            "to fix permissions (or use `sudo guardian status`)")
    settle(config, state, persist=(TESTING or os.geteuid() == 0))
    if state.get("emergency_at") is not None:
        dl = emergency_deadline(config, state)
        mode = "COOLING-OFF → disarms %s" % fmt_ts(dl)
    elif not state["armed"]:
        mode = "DISARMED"
    elif state.get("pause_until"):
        mode = "PAUSED → re-arms %s" % fmt_ts(state["pause_until"])
    else:
        mode = "ARMED"
    print("guardian: %s" % mode)
    print("blocked domains (%d): %s" % (
        len(config["domains"]), ", ".join(sorted(config["domains"])) or "—"))
    print("nsfw filter: %s" % (
        "on (Cloudflare Family DNS)" if config.get("filter") else "off"))
    print("service door: 127.0.0.1:%d (CLI only — `guardian door`)" % PROXY_PORT)
    left = codes_remaining()
    if left is None:
        print("unlock codes remaining: (visible with sudo)")
    else:
        print("unlock codes remaining: %d%s" % (left, "  ⚠ regenerate soon" if left < 5 else ""))


def parse_duration(s):
    m = re.fullmatch(r"(\d+)\s*(m|min|h|hr|hours?|minutes?)", s.strip(), re.I)
    if not m:
        die("duration like '30m' or '2h' expected")
    n = int(m.group(1))
    return n * (60 if m.group(2).lower().startswith("m") else 3600)


DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")


def cmd_add(args):
    if not args:
        die("usage: guardian add <domain>")
    need_root()
    config, state = load_all()
    d = args[0].lower().strip().removeprefix("https://").removeprefix("http://").strip("/")
    d = d.removeprefix("www.")
    if not DOMAIN_RE.match(d):
        die("that doesn't look like a domain: %s" % d)
    if d in config["domains"]:
        print("%s is already blocked" % d)
        return
    config["domains"].append(d)
    save_json(CONFIG, config)
    enforce_once()
    print("added %s — tightening is always free" % d)


def cmd_remove(args):
    if not args:
        die("usage: guardian remove <domain>")
    need_root()
    config, _ = load_all()
    d = args[0].lower().strip()
    if d not in config["domains"]:
        die("%s is not on the blocklist" % d)
    require_code("remove %s" % d)
    config["domains"].remove(d)
    save_json(CONFIG, config)
    enforce_once()
    print("removed %s" % d)


def cmd_arm(args):
    need_root()
    _, state = load_all()
    state["armed"] = True
    state["pause_until"] = None
    state["emergency_at"] = None
    save_json(STATE, state)
    enforce_once()
    print("ARMED. Arrows out of this state cost a code or a day.")


def cmd_disarm(args):
    need_root()
    require_code("disarm")
    _, state = load_all()
    state["armed"] = False
    state["emergency_at"] = None
    save_json(STATE, state)
    enforce_once()
    print("DISARMED. `guardian arm` re-enables (free, instant).")


def cmd_pause(args):
    if not args:
        die("usage: guardian pause <30m|2h>")
    need_root()
    secs = parse_duration(args[0])
    if secs > 8 * 3600:
        die("pauses are capped at 8h — use `guardian disarm` for longer")
    require_code("pause for %s" % args[0])
    _, state = load_all()
    state["pause_until"] = time.time() + secs
    save_json(STATE, state)
    enforce_once()
    print("paused until %s — auto re-arms" % fmt_ts(state["pause_until"]))


def cmd_delay(args):
    if not args:
        die("usage: guardian delay <30m|2h|24h>")
    need_root()
    config, state = load_all()
    secs = parse_duration(args[0])
    if secs < 30 * 60:
        die("minimum emergency delay is 30m")
    current = config.get("emergency_delay_hours", 24) * 3600
    if secs < current and is_active(state):
        # Shortening the hatch is loosening — free shortening would be
        # a self-serve bypass of the whole cooling-off idea.
        require_code("shorten the emergency delay to %s" % args[0])
    config["emergency_delay_hours"] = secs / 3600
    save_json(CONFIG, config)
    print("emergency delay is now %s%s" % (
        args[0], "" if secs >= current else " — shorter hatch, weaker guardian; your call"))


def cmd_door(args):
    print("service door: http://127.0.0.1:%d — a CONNECT proxy the daemon runs" % PROXY_PORT)
    print("CLI tools go through the wall with one env var:")
    print("  HTTPS_PROXY=http://127.0.0.1:%d yt-dlp <url>" % PROXY_PORT)
    print("  HTTPS_PROXY=http://127.0.0.1:%d curl https://reddit.com/" % PROXY_PORT)
    print("browsers stay walled: they use the system resolver, the daemon clears")
    print("any system proxy aimed at the door, and the door refuses Mozilla UAs.")


def cmd_filter(args):
    if not args or args[0] not in ("on", "off"):
        die("usage: guardian filter <on|off>")
    need_root()
    config, state = load_all()
    want = args[0] == "on"
    if config.get("filter", False) == want:
        print("nsfw filter is already %s" % args[0])
        return
    if not want and is_active(state):
        # Same asymmetry as everything else: on = tightening, off = loosening.
        require_code("turn the nsfw filter off")
    config["filter"] = want
    save_json(CONFIG, config)
    enforce_once()
    if want:
        print("nsfw filter ON — DNS pinned to Cloudflare Family (1.1.1.3); "
              "all other resolvers blocked.")
        if not is_active(state):
            print("(enforced once you `guardian arm`)")
        print("note: captive portals (hotel/café wi-fi) may need `guardian pause` to log in")
    else:
        print("nsfw filter off — DNS back to DHCP defaults")


def cmd_emergency(args):
    need_root()
    config, state = load_all()
    if args and args[0] == "cancel":
        if state.get("emergency_at") is None:
            die("no emergency pending")
        state["emergency_at"] = None
        save_json(STATE, state)
        print("emergency canceled. Nice.")
        return
    if state.get("emergency_at") is not None:
        die("emergency already pending — disarms %s" % fmt_ts(emergency_deadline(config, state)))
    state["emergency_at"] = time.time()
    save_json(STATE, state)
    print("Emergency requested. Blocks stay enforced until %s, then DISARMED."
          % fmt_ts(emergency_deadline(config, state)))
    print("`guardian emergency cancel` is free until then.")


def print_batch(plain):
    print()
    print("Guardian Angel — one-time unlock codes (batch of %d)" % len(plain))
    print("Send this list to your friend, then delete it. It is never shown again.")
    print()
    for i in range(0, len(plain), 4):
        print("  " + "     ".join(plain[i:i + 4]))
    print()
    print("Stored locally: salted SHA-256 hashes only.")


def cmd_init(args):
    need_root()
    os.makedirs(APP_DIR, exist_ok=True)
    if os.path.exists(CODES) and codes_remaining() > 0 and "--force" not in args:
        die("already initialized (codes exist). Use `guardian regen` to rotate the batch.")
    config, state = load_all()
    save_json(CONFIG, config)
    save_json(STATE, state)
    print_batch(gen_batch())
    print("Next: `guardian add <domain>` … then `guardian arm`.")


def cmd_regen(args):
    need_root()
    _, state = load_all()
    if is_active(state):
        # Otherwise "regen and peek at the fresh list" would be a free bypass.
        require_code("regenerate the code batch")
    print_batch(gen_batch())


def plist_dict():
    return {
        "Label": LABEL,
        "ProgramArguments": [sys.executable or "/usr/bin/python3",
                             os.path.join(INSTALL_DIR, "guardian.py"), "daemon"],
        "RunAtLoad": True,
        "KeepAlive": True,
        "StandardOutPath": LOG,
        "StandardErrorPath": LOG,
    }


def cmd_install(args):
    need_root()
    os.makedirs(INSTALL_DIR, exist_ok=True)
    os.makedirs(LAUNCHD_DIR, exist_ok=True)
    os.makedirs(APP_DIR, exist_ok=True)
    shutil.copyfile(os.path.abspath(__file__), os.path.join(INSTALL_DIR, "guardian.py"))
    os.chmod(os.path.join(INSTALL_DIR, "guardian.py"), 0o755)
    with open(PF_RULES, "w") as f:
        f.write(pf_rules_text(load_json(CONFIG, DEFAULT_CONFIG).get("filter", False)))
    with open(CANONICAL_PLIST, "wb") as f:
        plistlib.dump(plist_dict(), f)
    shutil.copyfile(CANONICAL_PLIST, PLIST)
    os.chmod(PLIST, 0o644)
    for path, mode in ((CONFIG, 0o644), (STATE, 0o644), (CODES, 0o600)):
        if os.path.exists(path):
            os.chmod(path, mode)
    if not TESTING:
        if os.path.islink(BIN_LINK) or os.path.exists(BIN_LINK):
            os.remove(BIN_LINK)
        os.symlink(os.path.join(INSTALL_DIR, "guardian.py"), BIN_LINK)
        run(["launchctl", "bootstrap", "system", PLIST])
        run(["launchctl", "enable", "system/" + LABEL])
        # -k restarts a daemon that was already running, so upgrades
        # actually pick up the new code instead of the old process.
        run(["launchctl", "kickstart", "-k", "system/" + LABEL])
    print("Installed. Daemon is running under launchd (KeepAlive).")
    print("Next: `guardian init` if you haven't, then add domains and `guardian arm`.")


def cmd_uninstall(args):
    need_root()
    config, state = load_all()
    settle(config, state)
    if is_active(state):
        die("refusing while ARMED. Exit paths: a code (`guardian disarm`) "
            "or `guardian emergency` (24h).")
    run(["launchctl", "bootout", "system/" + LABEL])
    for p in (PLIST,):
        try:
            os.remove(p)
        except FileNotFoundError:
            pass
    # strip hosts + pf
    rest, _ = split_hosts(read_hosts())
    write_hosts(rest, None)
    flush_dns()
    ensure_dns_pin(False)
    if not TESTING:
        run(["pfctl", "-a", "guardian-angel", "-F", "all"])
        try:
            with open(PF_CONF) as f:
                conf = f.read()
            new = "\n".join(l for l in conf.splitlines() if l not in PF_ANCHOR_LINES)
            with open(PF_CONF, "w") as f:
                f.write(new + "\n")
            run(["pfctl", "-f", PF_CONF])
        except FileNotFoundError:
            pass
        if os.path.islink(BIN_LINK):
            os.remove(BIN_LINK)
    shutil.rmtree(INSTALL_DIR, ignore_errors=True)
    shutil.rmtree(APP_DIR, ignore_errors=True)
    print("Uninstalled cleanly. It was guarding you the whole time.")


# ---------------------------------------------------------------- main

COMMANDS = {
    "status": cmd_status,
    "add": cmd_add,
    "remove": cmd_remove,
    "arm": cmd_arm,
    "disarm": cmd_disarm,
    "pause": cmd_pause,
    "emergency": cmd_emergency,
    "delay": cmd_delay,
    "filter": cmd_filter,
    "door": cmd_door,
    "init": cmd_init,
    "regen": cmd_regen,
    "install": cmd_install,
    "uninstall": cmd_uninstall,
    "daemon": cmd_daemon,
}

USAGE = """guardian — network-level site blocking with friend-held keys

  status                  state, blocklist, codes remaining      free
  add <domain>            block a domain                         free
  arm                     enable enforcement                     free
  pause <30m|2h>          bounded window, auto re-arms           one code
  remove <domain>         unblock a domain                       one code
  disarm                  enforcement off until re-armed         one code
  emergency [cancel]      no code — disarm lands after the delay time
  delay <30m|2h|24h>      set the emergency delay                raise free / lower one code
  filter <on|off>         nsfw filter (Cloudflare Family DNS)    on free / off one code
  door                    how terminals get through the wall     info
  init | regen            create / rotate the one-time codes
  install | uninstall     manage the daemon (uninstall: DISARMED only)
"""


def main():
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help", "help"):
        print(USAGE)
        return
    fn = COMMANDS.get(args[0])
    if fn is None:
        die("unknown command %r — try `guardian help`" % args[0])
    fn(args[1:])


if __name__ == "__main__":
    main()
