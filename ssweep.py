#!/usr/bin/env python3
"""ssweep - see what is listening / running / left over (ports, docker, services) and clean it up.

  ssweep.py                 overview: ports, containers, images, services
  ssweep.py -a              ...including every running service
  ssweep.py --json          machine-readable overview
  ssweep.py clean           pick items by number -> stop / remove them
  ssweep.py free 8080       stop whatever owns port 8080 (container, service or process)

Python 3 stdlib only. Ports are read from /proc (no ss needed). Run with sudo to see
the owner of every port. Docker is used through the `docker` CLI if available.
"""
__version__ = "0.1.0"

import argparse, ipaddress, json, os, re, shutil, signal, subprocess, sys

# ----------------------------------------------------------------- output helpers
COLOR = sys.stdout.isatty() and "NO_COLOR" not in os.environ
def _c(code): return lambda t: f"\033[{code}m{t}\033[0m" if COLOR else str(t)
bold, dim, red, green, yellow, cyan = _c("1"), _c("2"), _c("31"), _c("32"), _c("33"), _c("36")

def cut(s, n): s = str(s); return s if len(s) <= n else s[:n - 1] + "…"

def table(headers, rows, indent=2):
    """rows: list of lists; a cell is str or (str, style_fn)."""
    txt = lambda x: x[0] if isinstance(x, tuple) else str(x)
    w = [max([len(h)] + [len(txt(r[i])) for r in rows]) for i, h in enumerate(headers)]
    pad = " " * indent
    print(pad + dim("  ".join(h.ljust(w[i]) for i, h in enumerate(headers)).rstrip()))
    for r in rows:
        cells = []
        for i, x in enumerate(r):
            s = txt(x).ljust(w[i]) if i < len(r) - 1 else txt(x)
            cells.append((x[1] or str)(s) if isinstance(x, tuple) else s)
        print(pad + "  ".join(cells))

def section(title, extra=""):
    print("\n" + bold(title) + ("  " + dim(extra) if extra else ""))

def run(cmd, timeout=30):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr.strip()
    except FileNotFoundError:
        return 127, "", f"{cmd[0]}: not found"
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"

def priv(cmd):
    return cmd if os.geteuid() == 0 or not shutil.which("sudo") else ["sudo"] + cmd

# ----------------------------------------------------------------- docker
DOCKER_ERR = None
PORT_RE = re.compile(r'(?:(\[[^\]]+\]|[\d.]+|::):)?(\d+)(?:-(\d+))?->(\d+)(?:-(\d+))?/(tcp|udp)')

def docker_lines(args):
    global DOCKER_ERR
    rc, out, err = run(["docker"] + args)
    if rc:
        if "not found" in err: DOCKER_ERR = "docker is not installed"
        elif "permission denied" in err.lower(): DOCKER_ERR = "permission denied - run with sudo or join the docker group"
        else: DOCKER_ERR = (err.splitlines() or ["docker failed"])[-1]
        return None
    return [l for l in out.splitlines() if l.strip()]

def docker_json(args):
    lines = docker_lines(args + ["--format", "{{json .}}"])
    return None if lines is None else [json.loads(l) for l in lines]

def get_containers():
    rows = docker_json(["ps", "-a", "--no-trunc"])
    if rows is None: return None
    return [{"id": r["ID"], "short": r["ID"][:12], "name": r["Names"], "image": r["Image"], "state": r["State"],
             "status": r["Status"], "ports": r.get("Ports", ""), "created": r.get("RunningFor", "")} for r in rows]

def get_images(containers):
    rows = docker_json(["images", "--no-trunc"])
    if rows is None: return None
    used = set()
    if containers:
        lines = docker_lines(["inspect", "--format", "{{.Image}}"] + [c["id"] for c in containers])
        if lines and len(lines) == len(containers): used = set(lines)
        else: used = None                      # unknown -> never call anything unused
    out = []
    for r in rows:
        dangling = r["Repository"] == "<none>"
        name = "<none>" if dangling else f'{r["Repository"]}:{r["Tag"]}'
        state = "dangling" if dangling else ("in use" if used is None or r["ID"] in used else "unused")
        if dangling and used is not None and r["ID"] in used: state = "in use"
        out.append({"id": r["ID"], "short": r["ID"].replace("sha256:", "")[:12], "name": name, "size": r["Size"],
                    "created": r.get("CreatedSince", ""), "state": state})
    return out

def published(containers):
    m = {}
    for c in containers:
        if c["state"] != "running": continue
        for g in PORT_RE.finditer(c["ports"]):
            ip, h1, h2, c1, _, proto = g.groups()
            h1 = int(h1); h2 = int(h2 or h1)
            for i, p in enumerate(range(h1, h2 + 1)):
                m[(proto, p)] = (c, int(c1) + i, (ip or "0.0.0.0").strip("[]"))
    return m

def fmt_ports(s):
    seen = []
    for g in PORT_RE.finditer(s):
        ip, h1, h2, c1, c2, proto = g.groups()
        t = f"{h1}{'-' + h2 if h2 else ''}->{c1}{'-' + c2 if c2 else ''}{'' if proto == 'tcp' else '/udp'}"
        if (ip or "").startswith("127."): t += " (local)"
        if t not in seen: seen.append(t)
    return ", ".join(seen) or "-"

# ----------------------------------------------------------------- host ports (/proc)
WILD = {"0.0.0.0", "::", "*"}

def parse_addr(h, v6):
    b = bytes.fromhex(h)
    if not v6: return str(ipaddress.IPv4Address(b[::-1]))
    return str(ipaddress.IPv6Address(b"".join(b[i:i + 4][::-1] for i in range(0, 16, 4))))

def read_sockets():
    socks = []
    for name, v6 in (("tcp", 0), ("tcp6", 1), ("udp", 0), ("udp6", 1)):
        try:
            with open(f"/proc/net/{name}") as fh: lines = fh.read().splitlines()[1:]
        except OSError: continue
        base = name.rstrip("6")
        for ln in lines:
            f = ln.split()
            if len(f) < 10: continue
            la, lp = f[1].split(":")
            if base == "tcp" and f[3] != "0A": continue                              # LISTEN only
            if base == "udp" and (f[3] != "07" or f[2].split(":")[1] != "0000"): continue  # unconnected
            if int(lp, 16) == 0: continue
            socks.append({"proto": base, "addr": parse_addr(la, v6), "port": int(lp, 16), "inode": int(f[9])})
    return socks

def inode_pids(inodes):
    res = {}
    for pid in os.listdir("/proc"):
        if not pid.isdigit(): continue
        try: fds = os.listdir(f"/proc/{pid}/fd")
        except OSError: continue
        for fd in fds:
            try: l = os.readlink(f"/proc/{pid}/fd/{fd}")
            except OSError: continue
            if l.startswith("socket:["):
                ino = int(l[8:-1])
                if ino in inodes and ino not in res: res[ino] = int(pid)
    return res

def rd(path):
    try:
        with open(path, "rb") as fh: return fh.read().decode(errors="replace")
    except OSError: return ""

def unit_from_cgroup(cg):
    units = [u for u in re.findall(r'/([^/\n]+\.service)', cg) if not u.startswith("user@")]
    return units[-1] if units else None

def get_ports(containers, pub):
    socks = read_sockets()
    pids = inode_pids({s["inode"] for s in socks})
    by_id = {c["id"]: c for c in containers}
    merged = {}
    for s in socks:
        pid = pids.get(s["inode"])
        proc = rd(f"/proc/{pid}/comm").strip() if pid else "?"
        cmd = rd(f"/proc/{pid}/cmdline").replace("\0", " ").strip() if pid else ""
        cg = rd(f"/proc/{pid}/cgroup") if pid else ""
        hit = pub.get((s["proto"], s["port"]))
        m = re.search(r'docker[-/]([0-9a-f]{64})', cg)
        if proc == "docker-proxy" and hit:
            kind, owner, oid = "container", hit[0]["name"], hit[0]["id"]
        elif m and m.group(1) in by_id:
            c = by_id[m.group(1)]; kind, owner, oid = "container", c["name"], c["id"]
        elif unit_from_cgroup(cg):
            kind, owner, oid = "service", unit_from_cgroup(cg), unit_from_cgroup(cg)
        elif pid:
            kind, owner, oid = "process", proc, str(pid)
        else:
            kind, owner, oid = "unknown", "?", ""
        key = (s["proto"], s["port"], kind, owner, pid)
        r = merged.setdefault(key, {"port": s["port"], "proto": s["proto"], "binds": set(), "kind": kind,
                                    "owner": owner, "owner_id": oid, "pid": pid, "proc": proc, "cmd": cmd})
        r["binds"].add(s["addr"])
    have = {(r["proto"], r["port"]) for r in merged.values()}
    for (proto, port), (c, _, ip) in pub.items():            # published via iptables only (no host socket)
        if (proto, port) not in have:
            merged[(proto, port, "container", c["name"], None)] = {
                "port": port, "proto": proto, "binds": {ip}, "kind": "container", "owner": c["name"],
                "owner_id": c["id"], "pid": None, "proc": "(iptables)", "cmd": ""}
    rows = sorted(merged.values(), key=lambda r: (r["port"], r["proto"]))
    for r in rows: r["binds"] = sorted(r["binds"])
    return rows

def bind_label(binds):
    if set(binds) & WILD: return ("ALL", yellow)
    if all(b.startswith("127.") or b == "::1" for b in binds): return ("local", green)
    return (",".join(binds), None)

# ----------------------------------------------------------------- services
SYSTEM_RE = re.compile(r'^(systemd|dbus|NetworkManager|polkit|ModemManager|wpa_supplicant|avahi|udisks|upower|'
                       r'accounts-daemon|colord|rtkit|gdm|lightdm|sddm|getty|user@|docker|containerd)')

def get_services(ports):
    rc, out, _ = run(["systemctl", "list-units", "--type=service", "--state=running", "--no-legend", "--plain", "--no-pager"])
    if rc: return None
    svcs = []
    for ln in out.splitlines():
        f = ln.split(None, 4)
        if len(f) < 4: continue
        mine = sorted({r["port"] for r in ports if r["kind"] == "service" and r["owner"] == f[0]})
        svcs.append({"unit": f[0], "desc": f[4] if len(f) > 4 else "", "ports": mine, "system": bool(SYSTEM_RE.match(f[0]))})
    return svcs

# ----------------------------------------------------------------- collect
def collect(all_services=False):
    global DOCKER_ERR
    DOCKER_ERR = None
    containers = get_containers()
    images = get_images(containers) if containers is not None else None
    err = DOCKER_ERR
    pub = published(containers or [])
    ports = get_ports(containers or [], pub)
    services = get_services(ports)
    if services is not None and not all_services:
        services = [s for s in services if s["ports"]]
    return {"ports": ports, "containers": containers, "images": images, "services": services, "docker_error": err}

# ----------------------------------------------------------------- show
def cmd_show(a):
    d = collect(a.all)
    if a.json:
        print(json.dumps(d, indent=2)); return
    ports, cs, ims, svcs = d["ports"], d["containers"], d["images"], d["services"]
    run_n = sum(c["state"] == "running" for c in cs or [])
    unused = sum(i["state"] in ("unused", "dangling") for i in ims or [])
    print(bold("ssweep") + "  " + dim(f"{len(ports)} ports | {run_n}/{len(cs or [])} containers running | "
          f"{len(ims or [])} images ({unused} unused) | {len(svcs or [])} services"))

    section("PORTS", "listening on this host")
    if ports:
        rows, unknown = [], 0
        for r in ports:
            if r["kind"] == "unknown": unknown += 1
            tstyle = {"container": cyan, "service": green, "unknown": red}.get(r["kind"])
            rows.append([(str(r["port"]), bold), r["proto"], bind_label(r["binds"]), (r["kind"], tstyle),
                         cut(r["owner"], 28), str(r["pid"] or "-"), dim(cut(r["cmd"], 45)) if r["kind"] == "process" else ""])
        table(["PORT", "PROTO", "BIND", "TYPE", "NAME", "PID", "COMMAND"], rows)
        if unknown: print(dim(f"  {unknown} port(s) with unknown owner - run with sudo to resolve them"))
    else:
        print(dim("  nothing listening"))

    section("CONTAINERS", f"{run_n} running, {len(cs or []) - run_n} stopped" if cs is not None else "")
    if cs is None: print(dim(f"  {d['docker_error']}"))
    elif not cs: print(dim("  none"))
    else:
        rows = [[(c["name"], bold), cut(c["image"], 30), (c["state"], green if c["state"] == "running" else yellow),
                 cut(c["status"], 26), fmt_ports(c["ports"]), c["short"]] for c in cs]
        table(["NAME", "IMAGE", "STATE", "STATUS", "PORTS", "ID"], rows)

    section("IMAGES", f"{unused} unused / dangling" if ims is not None else "")
    if ims is None: print(dim(f"  {d['docker_error']}"))
    elif not ims: print(dim("  none"))
    else:
        st = {"in use": green, "unused": yellow, "dangling": red}
        table(["NAME", "ID", "SIZE", "CREATED", "STATUS"],
              [[(cut(i["name"], 40), bold), i["short"], i["size"], i["created"], (i["state"], st[i["state"]])] for i in ims])

    section("SERVICES", "running" + ("" if a.all else ", with open ports (-a for all)"))
    if svcs is None: print(dim("  systemd not available"))
    elif not svcs: print(dim("  none"))
    else:
        table(["UNIT", "PORTS", "DESCRIPTION"], [[(s["unit"], bold), ",".join(map(str, s["ports"])) or "-", cut(s["desc"], 50)] for s in svcs])
    print("\n" + dim("next: ssweep clean  |  ssweep free <port>"))

# ----------------------------------------------------------------- actions
def kill_pid(pid):
    try:
        os.kill(int(pid), signal.SIGTERM); return True, "SIGTERM sent"
    except ProcessLookupError: return True, "already gone"
    except PermissionError:
        rc, _, err = run(priv(["kill", str(pid)])); return rc == 0, err or "SIGTERM sent (sudo)"

def perform(item, mode):
    """mode: 'stop' (keep it) or 'rm' (remove it). Returns (ok, message)."""
    k = item["kind"]
    if k == "container":
        if mode == "stop":
            if item.get("state") not in (None, "running"): return True, "already stopped"
            cmd = ["docker", "stop", item["id"]]
        else: cmd = ["docker", "rm", "-f", item["id"]]
    elif k == "image":
        if mode == "stop": return False, "images cannot be stopped (use remove)"
        cmd = ["docker", "rmi", item["ref"]]
    elif k == "service": cmd = priv(["systemctl", "stop", item["id"]])
    elif k == "process": return kill_pid(item["id"])
    else: return False, "unknown owner (try sudo)"
    rc, _, err = run(cmd, 120)
    return rc == 0, (err.splitlines() or [""])[-1] if rc else "done"

def items_from_ports(ports, containers):
    cstate = {c["id"]: c["state"] for c in containers or []}
    seen, items = set(), []
    for r in ports:
        if r["kind"] == "unknown": continue
        key = (r["kind"], r["owner_id"])
        if key in seen: continue
        seen.add(key)
        if r["kind"] == "process" and int(r["owner_id"]) in (1, os.getpid()): continue
        if r["kind"] == "service" and SYSTEM_RE.match(r["owner"]): continue
        items.append({"kind": r["kind"], "id": r["owner_id"], "name": r["owner"], "state": cstate.get(r["owner_id"]),
                      "info": ("port " + ",".join(str(x["port"]) for x in ports if (x["kind"], x["owner_id"]) == key))
                      + (f" | {r['cmd'][:40]}" if r["kind"] == "process" else "")})
    return items

CAT_ORDER = {"containers": 0, "images": 1, "services": 2, "ports": 3}

def build_clean_items(d):
    items = []
    cstate = {c["id"]: c["state"] for c in d["containers"] or []}
    for c in d["containers"] or []:
        items.append({"cat": "containers", "kind": "container", "id": c["id"], "name": c["name"], "state": c["state"],
                      "info": f'{cut(c["image"], 22)} | {cut(c["status"], 24)} | {fmt_ports(c["ports"])}'})
    for i in d["images"] or []:
        if i["state"] in ("unused", "dangling"):
            items.append({"cat": "images", "kind": "image", "id": i["id"], "ref": i["id"] if i["state"] == "dangling" else i["name"],
                          "name": cut(i["name"], 30), "state": i["state"], "info": f'{i["size"]} | {i["state"]} | {i["created"]}'})
    for sv in d["services"] or []:
        if sv["system"]: continue
        ports = ("ports " + ",".join(map(str, sv["ports"]))) if sv["ports"] else "no open ports"
        items.append({"cat": "services", "kind": "service", "id": sv["unit"], "name": sv["unit"], "state": "running",
                      "info": f'{ports} | {cut(sv["desc"], 35)}'})
    seen = set()
    for p in d["ports"]:                                   # one row per port, whoever owns it
        if p["kind"] == "unknown": continue
        if p["kind"] == "service" and SYSTEM_RE.match(p["owner"]): continue
        if p["kind"] == "process" and int(p["owner_id"]) in (1, os.getpid()): continue
        key = (p["port"], p["proto"], p["kind"], p["owner_id"])
        if key in seen: continue
        seen.add(key)
        items.append({"cat": "ports", "kind": p["kind"], "id": p["owner_id"], "name": f'{p["port"]}/{p["proto"]}',
                      "state": cstate.get(p["owner_id"], "running"), "force_mode": "stop", "owner": p["owner"],
                      "info": f'{bind_label(p["binds"])[0]} | {p["kind"]} {cut(p["owner"], 24)}' + (f' | {cut(p["cmd"], 30)}' if p["kind"] == "process" else "")})
    return items

def action_label(i, mode="rm"):
    if i.get("force_mode"): return ("kill " if i["kind"] == "process" else "stop ") + cut(i["owner"], 22)
    return "stop only" if mode == "stop" else ACTION[i["kind"]](i)

    items = []
    for c in d["containers"] or []:
        items.append({"kind": "container", "id": c["id"], "name": c["name"], "state": c["state"],
                      "info": f'{cut(c["image"], 22)} | {cut(c["status"], 24)} | {fmt_ports(c["ports"])}'})
    for i in d["images"] or []:
        if i["state"] in ("unused", "dangling"):
            items.append({"kind": "image", "id": i["id"], "ref": i["id"] if i["state"] == "dangling" else i["name"],
                          "name": cut(i["name"], 30), "state": i["state"], "info": f'{i["size"]} | {i["state"]} | {i["created"]}'})
    host = [r for r in d["ports"] if r["kind"] in ("service", "process")]
    items += items_from_ports(host, d["containers"])
    return items

ACTION = {"container": lambda i: "stop+remove" if i["state"] == "running" else "remove",
          "image": lambda i: "remove", "service": lambda i: "stop", "process": lambda i: "kill"}
ORDER = {"container": 0, "image": 1, "service": 2, "process": 3}

def parse_selection(s, n):
    sel = []
    for tok in s.replace(",", " ").split():
        m = re.fullmatch(r'(s)?(\d+)(?:-(\d+))?', tok.lower())
        if not m: raise ValueError(f"cannot parse '{tok}'")
        a, b = int(m.group(2)), int(m.group(3) or m.group(2))
        if not (1 <= a <= b <= n): raise ValueError(f"'{tok}' is out of range 1-{n}")
        sel += [(i, "stop" if m.group(1) else "rm") for i in range(a, b + 1)]
    return sel

def confirm(msg, yes):
    return yes or input(msg + " [y/N] ").strip().lower() in ("y", "yes")

MENU = [("1", "containers"), ("2", "images"), ("3", "services"), ("4", "ports"), ("a", "all")]

def cmd_clean(a):
    cat = a.what
    while True:
        d = collect(True)
        if d["docker_error"]: print(dim(f"docker: {d['docker_error']}"))
        every = build_clean_items(d)
        if cat is None:                                    # category menu
            n = {k: sum(i["cat"] == k for i in every) for k in CAT_ORDER}
            n_all = sum(i["cat"] != "ports" or i["kind"] == "process" for i in every)
            print("\n" + bold("what do you want to clean?"))
            for key, name in MENU:
                print(f"  {bold(key)}) {name:<11}" + dim(f" {n.get(name, n_all)}"))
            print(f"  {bold('q')}) quit")
            try: ch = input("clean> ").strip().lower()
            except (EOFError, KeyboardInterrupt): print(); return 0
            if ch in ("q", "quit", ""): return 0
            cat = next((name for key, name in MENU if ch in (key, name)), None)
            if cat is None: print(red("unknown choice")); continue
        items = [i for i in every if cat == "all" and (i["cat"] != "ports" or i["kind"] == "process") or i["cat"] == cat]
        items.sort(key=lambda i: CAT_ORDER[i["cat"]])
        if not items:
            print(f"nothing to clean in '{cat}'.")
        else:
            table(["#", "TYPE", "NAME", "ACTION", "INFO"],
                  [[(str(n), bold), i["kind"], cut(i["name"], 28), (action_label(i), yellow), dim(i["info"])] for n, i in enumerate(items, 1)])
            print(dim("\n  pick: 1 3 5-7   |   s2 = stop only (keep it)   |   q = back"))
            try:
                raw = input("select> ").strip()
                sel = [] if raw.lower() in ("", "q", "quit", "back") else parse_selection(raw, len(items))
            except ValueError as e:
                print(red(str(e))); sel = []
            except (EOFError, KeyboardInterrupt):
                print(); return 0
            if sel:
                sel = sorted(set(sel), key=lambda t: (CAT_ORDER[items[t[0] - 1]["cat"]], t[0]))
                print("\nwill do:")
                for n, mode in sel:
                    i = items[n - 1]
                    print(f"  {i['kind']:<10} {cut(i['name'], 30):<30} -> {action_label(i, mode)}")
                if confirm("proceed?", a.yes):
                    for n, mode in sel:
                        i = items[n - 1]
                        ok, msg = perform(i, i.get("force_mode") or mode)
                        print(f"  {green('ok  ') if ok else red('fail')} {i['kind']} {i['name']}: {msg}")
                else:
                    print("aborted.")
        if a.what is not None: return 0                    # direct mode: one round, then exit
        cat = None
    d = collect(True)
    items = build_clean_items(d)
    if d["docker_error"]: print(dim(f"docker: {d['docker_error']}"))
    if not items:
        print("nothing to clean."); return 0
    items.sort(key=lambda i: ORDER[i["kind"]])
    table(["#", "TYPE", "NAME", "ACTION", "INFO"],
          [[(str(n), bold), i["kind"], cut(i["name"], 28), (ACTION[i["kind"]](i), yellow), dim(i["info"])] for n, i in enumerate(items, 1)])
    print(dim("\n  pick: 1 3 5-7   |   s2 = stop only (keep it)   |   q = quit"))
    try:
        raw = input("select> ").strip()
        if raw.lower() in ("", "q", "quit"): return 0
        sel = parse_selection(raw, len(items))
    except ValueError as e:
        print(red(str(e))); return 1
    except (EOFError, KeyboardInterrupt):
        print(); return 0
    sel = sorted(set(sel), key=lambda t: (ORDER[items[t[0] - 1]["kind"]], t[0]))
    print("\nwill do:")
    for n, mode in sel:
        i = items[n - 1]
        print(f"  {i['kind']:<10} {cut(i['name'], 30):<30} -> {'stop only' if mode == 'stop' else ACTION[i['kind']](i)}")
    if not confirm("proceed?", a.yes): print("aborted."); return 1
    bad = 0
    for n, mode in sel:
        i = items[n - 1]
        ok, msg = perform(i, mode)
        bad += not ok
        print(f"  {green('ok  ') if ok else red('fail')} {i['kind']} {i['name']}: {msg}")
    return 1 if bad else 0

def cmd_free(a):
    d = collect(True)
    rows = [r for r in d["ports"] if r["port"] == a.port]
    if not rows:
        print(f"nothing is listening on port {a.port}"); return 1
    if any(r["kind"] == "unknown" for r in rows): print(yellow("owner unknown - rerun with sudo"))
    items = items_from_ports(rows, d["containers"])
    for r in rows:
        if r["kind"] == "service" and SYSTEM_RE.match(r["owner"]) and not a.force:
            print(red(f"{r['owner']} is a system service; use --force to stop it anyway")); return 1
    if a.force:
        items = [{"kind": r["kind"], "id": r["owner_id"], "name": r["owner"], "state": "running"} for r in rows if r["kind"] != "unknown"]
    mode = "rm" if a.rm else "stop"
    for i in items:
        what = "stop" if i["kind"] in ("container", "service") and not a.rm else ("remove" if i["kind"] == "container" else "kill" if i["kind"] == "process" else "stop")
        print(f"port {a.port}: {i['kind']} {i['name']} -> {what}")
    if not confirm("proceed?", a.yes): print("aborted."); return 1
    bad = 0
    for i in items:
        ok, msg = perform(i, mode); bad += not ok
        print(f"  {green('ok  ') if ok else red('fail')} {i['name']}: {msg}")
    return 1 if bad else 0

def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("-a", "--all", action="store_true", help="show every running service")
    p.add_argument("--json", action="store_true", help="machine-readable overview")
    p.add_argument("-V", "--version", action="version", version=f"ssweep {__version__}")
    sub = p.add_subparsers(dest="cmd")
    sh = sub.add_parser("show", help="overview (default)")
    sh.add_argument("-a", "--all", action="store_true", default=argparse.SUPPRESS)
    sh.add_argument("--json", action="store_true", default=argparse.SUPPRESS)
    sh.set_defaults(fn=cmd_show)
    c = sub.add_parser("clean", help="interactively stop/remove things")
    c.add_argument("what", nargs="?", choices=["containers", "images", "services", "ports", "all"], help="skip the menu")
    c.add_argument("-y", "--yes", action="store_true"); c.set_defaults(fn=cmd_clean)
    f = sub.add_parser("free", help="stop whatever owns a port"); f.add_argument("port", type=int)
    f.add_argument("-y", "--yes", action="store_true"); f.add_argument("--rm", action="store_true", help="remove containers instead of stopping")
    f.add_argument("--force", action="store_true"); f.set_defaults(fn=cmd_free)
    a = p.parse_args()
    if not hasattr(a, "fn"): a.fn = cmd_show
    try:
        code = a.fn(a) or 0
        sys.stdout.flush()
    except BrokenPipeError:                      # e.g. `ssweep | head`
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        code = 0
    except KeyboardInterrupt:
        print(); code = 130
    sys.exit(code)

if __name__ == "__main__":
    main()
