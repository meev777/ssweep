# ssweep

![CI](https://github.com/meev777/ssweep/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![Platform](https://img.shields.io/badge/platform-linux-lightgrey)
![License](https://img.shields.io/badge/license-MIT-green)

**See everything that is still running on your machine, and clean it up.**
One readable view of open ports, Docker containers, Docker images and services, with one command to stop or delete what you forgot about.

- Single file, **Python standard library only**, nothing to install
- Replaces the unreadable `ss -tulpn` + `docker ps -a` + `docker images` + `systemctl` dance
- Links each port to its owner: **which container, service or process** is behind it
- Flags unused and dangling images, stopped containers and ports open to the whole network

> **Status: alpha (0.1.0).** Developed and unit-tested against mocked Docker output. Please report anything odd you hit on a real Docker setup.

---

## Why

When you work fast (labs, CTFs, tutorials, side projects) you start tools and containers without thinking, and later you have no idea what is still running, which port belongs to what, or which 700 MB image you will never use again. `ssweep` answers that in one screen and lets you fix it in one prompt.

## Demo

```text
$ ssweep
ssweep  4 ports | 2/3 containers running | 5 images (2 unused) | 0 services

PORTS  listening on this host
  PORT  PROTO  BIND   TYPE       NAME     PID  COMMAND
  5432  tcp    local  container  db       -
  8000  tcp    ALL    process    python3  201  python3 -m http.server 8000
  8080  tcp    ALL    container  web      -

CONTAINERS  2 running, 1 stopped
  NAME      IMAGE                 STATE    STATUS                  PORTS               ID
  web       nginx:latest          running  Up 3 days               8080->80            aaaaaaaaaaaa
  old-dvwa  vulnerables/web-dvwa  exited   Exited (0) 2 weeks ago  -                   bbbbbbbbbbbb
  db        postgres:16           running  Up 5 hours              5432->5432 (local)  cccccccccccc

IMAGES  2 unused / dangling
  NAME                           ID            SIZE   CREATED       STATUS
  nginx:latest                   111111111111  188MB  2 weeks ago   in use
  vulnerables/web-dvwa:latest    222222222222  712MB  5 years ago   in use
  postgres:16                    333333333333  431MB  1 month ago   in use
  kalilinux/kali-rolling:latest  444444444444  121MB  3 weeks ago   unused
  <none>                         555555555555  77MB   2 months ago  dangling

next: ssweep clean  |  ssweep free <port>
```

How to read the `PORTS` table:

| Column | Meaning |
|---|---|
| `BIND` | `ALL` = reachable from the network (0.0.0.0 / ::), `local` = only this machine (127.0.0.1 / ::1), otherwise the specific address |
| `TYPE` | who owns the port: `container`, `service` (systemd), `process`, or `unknown` (not enough permissions, see [Permissions](#permissions)) |
| `NAME` | container name, service unit, or process name |
| `COMMAND` | full command line, shown for plain processes |

Image status: `in use` (a container, running or stopped, uses it), `unused` (no container uses it), `dangling` (untagged leftover layers).

## Install

Requirements: **Linux**, **Python 3.9+**. Docker and systemd are optional (the sections are skipped when missing).

**Option 1 - just run it (no install)**

```bash
git clone https://github.com/meev777/ssweep.git
cd ssweep
python3 ssweep.py
```

**Option 2 - install the `ssweep` command with pipx** (recommended)

```bash
pipx install git+https://github.com/meev777/ssweep.git
ssweep
```

**Option 3 - install with pip from a clone**

```bash
git clone https://github.com/meev777/ssweep.git
cd ssweep
pip install .
ssweep
```

## Usage

| Command | What it does |
|---|---|
| `ssweep` | Overview: ports, containers, images, services |
| `ssweep -a` | Same, but list **every** running service (default: only services that own a port) |
| `ssweep --json` | Machine-readable overview |
| `ssweep clean` | Interactive: pick numbered items to stop or remove |
| `ssweep clean -y` | Same, without the final confirmation |
| `ssweep free <port>` | Stop whatever owns that port (container, service or process) |
| `ssweep free <port> --rm` | Same, but **delete** a container instead of stopping it |
| `ssweep -V` | Version |

Flags like `-a` and `--json` work before or after `show`.

### `ssweep clean`

Lists everything worth cleaning, numbered: containers, unused/dangling images, services and processes that hold open ports.

```text
$ ssweep clean
  #  TYPE       NAME                          ACTION       INFO
  1  container  old-dvwa                      remove       vulnerables/web-dvwa | Exited (0) 2 weeks ago | -
  2  container  db                            stop+remove  postgres:16 | Up 5 hours | 5432->5432 (local)
  3  image      kalilinux/kali-rolling:late…  remove       121MB | unused | 3 weeks ago
  4  image      <none>                        remove       77MB | dangling | 2 months ago

  pick: 1 3 5-7   |   s2 = stop only (keep it)   |   q = quit
select> 1 s2 3-4

will do:
  container  old-dvwa                       -> remove
  container  db                             -> stop only
  image      kalilinux/kali-rolling:latest  -> remove
  image      <none>                         -> remove
proceed? [y/N] y
  ok   container old-dvwa: done
  ok   container db: done
  ok   image kalilinux/kali-rolling:latest: done
  ok   image <none>: done
```

Selection syntax: `3` one item, `5-7` a range, `s2` **stop only** (keep the container), `q` quit. Without the `s` prefix:

| Type | Action |
|---|---|
| container | stop and delete (`docker rm -f`) |
| image | delete (`docker rmi`) |
| service | `systemctl stop` (not disabled, it comes back after reboot) |
| process | `SIGTERM` |

Nothing happens until you confirm the plan.

### `ssweep free <port>`

```text
$ ssweep free 8000
port 8000: process python3 -> kill
proceed? [y/N] y
  ok   python3: SIGTERM sent
```

## Permissions

- **Ports owned by other users** (root daemons, etc.) only show their owner if you run with `sudo`. Otherwise they appear as `unknown`, and the tool tells you.
- **Docker** needs access to the Docker socket: run with `sudo`, or add your user to the `docker` group. If access is denied, `ssweep` says so instead of failing.
- **Stopping services** uses `sudo systemctl stop ...` automatically when you are not root.

## Safety

- Always shows a plan and asks before acting (unless you pass `-y`).
- Core system services (systemd, dbus, NetworkManager, docker, ...) are **hidden from `clean`** and refused by `free` unless you add `--force`.
- If `ssweep` cannot tell which containers use an image, it never calls that image `unused`.
- It never touches volumes, networks, or images that a container still references.

## JSON output

`ssweep --json` prints:

```text
{
  "ports":      [ {"port", "proto", "binds", "kind", "owner", "owner_id", "pid", "proc", "cmd"}, ... ],
  "containers": [ {"id", "short", "name", "image", "state", "status", "ports", "created"}, ... ] | null,
  "images":     [ {"id", "short", "name", "size", "created", "state"}, ... ] | null,
  "services":   [ {"unit", "desc", "ports", "system"}, ... ] | null,
  "docker_error": "reason" | null
}
```

`null` means that source was not available (for example Docker not installed).

## How it works

- **Ports:** parsed directly from `/proc/net/{tcp,tcp6,udp,udp6}`; socket inodes are matched to PIDs through `/proc/<pid>/fd`. No `ss`/`netstat` needed.
- **Owner detection:** `/proc/<pid>/cgroup` identifies containers and systemd services; `docker-proxy` ports are matched to containers by their published ports. Ports Docker publishes through iptables only (no host socket) are added from `docker ps`.
- **Docker:** the `docker` CLI with `--format '{{json .}}'`. **Services:** `systemctl list-units`.

## Limitations

- Linux only (it reads `/proc`).
- Shows ports published to the host, not ports that only listen inside a container.
- Unix sockets and outgoing connections are out of scope.
- `ssweep` does not decide for you what is safe to delete. Read the plan.

## Development

```bash
git clone https://github.com/meev777/ssweep.git
cd ssweep
python3 -m unittest discover -s tests -v
```

Layout:

```text
ssweep.py              the whole tool
tests/test_ssweep.py   unit tests (no Docker needed)
pyproject.toml         packaging (provides the `ssweep` command)
.github/workflows/     CI on Python 3.9 - 3.13
```

## Roadmap

- `ssweep watch`: snapshot and diff, report what appeared or disappeared since last time
- Warnings for risky exposure (databases on `ALL`, privileged containers, `docker.sock` mounts)
- Docker volumes and networks

Issues and pull requests are welcome.

## License

[MIT](LICENSE)

ssweep - see what is listening / running / left over (ports, docker, services) and clean it up.

