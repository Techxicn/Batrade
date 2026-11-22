# Batrade Home-SOC

Batrade is a passive intrusion detection system for home and small-office networks. It monitors the local LAN, maintains a device inventory, detects known threat patterns, and delivers alerts via Telegram, Discord, or a local log file. It never blocks traffic.

## What it detects

- ARP spoofing (MAC-IP binding conflicts, gateway impersonation)
- ARP sweep / host enumeration
- SYN port scans
- Rogue DHCP servers
- Router reboots (gateway MAC change)
- New or unauthorized devices joining the network
- Risky open ports on known devices — TCP (Telnet, RDP, VNC, SMB…) and, with `CAP_NET_RAW`, UDP (UPnP/SSDP 1900, mDNS 5353)

## Requirements

- Python 3.11 or later.
- Linux with `nmap` and `iproute2` (`ip` ships with every desktop/server distribution).
- `arp-scan` for full live mode (optional — the sensor degrades gracefully without it).
- Python packages: `PyYAML`, `Flask`, `requests`, `defusedxml`, `scapy` (from the distribution or from a virtualenv).
- `CAP_NET_RAW` for live mode: passive capture, `arp-scan` and the UDP pass. Without it the sensor runs in `degraded` mode.

On distributions that mark the system interpreter as externally managed (PEP 668: Fedora, recent Debian/Ubuntu, Arch), use the `--venv` installer flag.

## Supported distributions

Batrade has no distribution-specific code: it only shells out to `iproute2` (`ip`), `nmap`, optionally `arp-scan` and (for the service guard) `systemctl`. The installer detects the distribution from `/etc/os-release` and picks the matching package manager:

| Family | Distributions | Manager | Packages |
|---|---|---|---|
| Debian | Debian, Ubuntu, Kali, Parrot, Mint, Pop!_OS | `apt` | `nmap arp-scan iproute2 python3 python3-venv python3-yaml python3-flask python3-requests python3-defusedxml python3-scapy` |
| Fedora / RHEL | Fedora, RHEL, CentOS Stream, Rocky, AlmaLinux | `dnf` | `nmap arp-scan iproute python3 python3-pyyaml python3-flask python3-requests python3-defusedxml python3-scapy` |
| Arch | Arch, BlackArch, Manjaro | `pacman` | `nmap arp-scan iproute2 python python-pyyaml python-flask python-requests python-defusedxml python-scapy` |
| openSUSE | Leap, Tumbleweed, SLES | `zypper` | `nmap arp-scan iproute2 python3 python3-PyYAML python3-Flask python3-requests python3-defusedxml python3-scapy` |
| Alpine | Alpine (edge) | `apk` | `nmap arp-scan iproute2 python3 py3-yaml py3-flask py3-requests py3-defusedxml py3-scapy` |

## Installation

### From the repository

```bash
bash install.sh                  # environment check + database (system Python)
bash install.sh --venv --link    # recommended for development: .venv + `batrade` in ~/.local/bin
bash install.sh --install-deps   # also installs nmap/arp-scan/iproute2 with the detected manager
bash install.sh --systemd        # installs the systemd units (root required)
```

The repository installer:

1. detects the distribution and package manager (apt, dnf, pacman, zypper, apk);
2. reports missing system tools and, with `--install-deps`, installs them;
3. verifies the Python modules (system interpreter or `.venv`);
4. creates `var/` and `.env` (mode 600) when missing and leaves `config.yaml` untouched;
5. initializes the database, lists the interfaces and runs `doctor`.

`--link` warns when the target directory is not in `PATH`. Re-running the installer is safe: it never replaces the database, the configuration or the secrets file.

### System-wide installation (machines and VMs)

```bash
sudo bash install.sh --system                          # install to /opt/batrade
sudo bash install.sh --system --install-deps --start   # + system packages, then start sensor and panel
sudo bash install.sh --system --prefix /srv/batrade --dry-run   # show the plan, change nothing
sudo bash install.sh --uninstall                       # remove code and command, keep var/, .env, config.yaml
sudo bash install.sh --uninstall --purge --yes         # also delete data and configuration
```

- Runs as root; otherwise it tells you to use `sudo`.
- Copies the repository **without** `.git`, `var/`, `.venv`, `.env` or build cruft, creates the virtualenv inside the prefix and installs the package there.
- Writes `/usr/local/bin/batrade` as a small wrapper that pins `BATRADE_ROOT` to the prefix and execs the venv binary, so `batrade` works from any directory. It warns if that directory is not in `PATH` (sudo commonly uses `secure_path`).
- **Upgrades preserve state**: an existing `config.yaml`, `.env` and `var/` are reused, never overwritten.
- `--dry-run` prints every step and changes nothing. `--start` launches sensor and dashboard at the end.
- `--uninstall` refuses while a CLI-managed component is alive, removes the wrapper and the code, and keeps `var/`, `.env` and `config.yaml`; `--purge` deletes those too after asking you to type `BORRAR` (`--yes` skips the prompt).

### Manual installation

Install the system packages from the table above, then:

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e .
python3 -m batrade init
```

## Quick start

This section assumes `batrade` is in `PATH` (from `--link` or `--system`); otherwise use `.venv/bin/batrade` or `python3 -m batrade`.

**1. Check what will be monitored.**

```bash
batrade interfaces
batrade doctor
```

`interfaces` lists every IPv4 interface with its kind (Ethernet, Wi-Fi, loopback), address and whether it carries the default route. `doctor` shows the interface, subnet, gateway, effective mode, effective user, schema version, heartbeat age and a "prueba en VM" block. `batrade init` is safe to repeat.

**2. Start both components in the background.**

```bash
batrade start
batrade status
```

`start` launches the sensor and the dashboard detached, with PID files in `var/` and logs in `var/log/`. `status` prints both PIDs, the heartbeat age, the effective user and mode, and the panel URL. Open **http://127.0.0.1:8000**:

| Route | Content |
|---|---|
| `/` | Summary: devices online, unknown/unauthorized, alerts today, latest events |
| `/devices` | Inventory with trust state, vendor, hostname, last seen |
| `/events` | Alert history with severity, verification state and false-positive marking |
| `/health` | Heartbeat, capabilities, mode, interface/subnet, tool status, UDP coverage |
| `/learning` | Baseline review and `approve-baseline` button |

Check it without a browser:

```bash
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8000/health
```

Stop or restart with `batrade stop` / `batrade restart`. Use `--only sensor` or `--only dashboard` to control one component, and `start --mode degraded` to force a sensor mode. If a component dies immediately (for example because port 8000 is taken), `start` prints the last lines of its log.

**3. Run in the foreground (optional).** Use two terminals; Ctrl+C stops each component.

```bash
batrade sensor       # prints the selected mode and interface
batrade dashboard    # http://127.0.0.1:8000
```

`auto` uses `live` when `CAP_NET_RAW` and `arp-scan` are available, otherwise `degraded` (netlink neighbor table + nmap TCP connect). The dashboard listens only on loopback by default; use `--host` / `--port` to change it, and exposing it beyond loopback requires `DASHBOARD_TOKEN` in `.env` (configuration validation refuses to start otherwise).

Logs live in `var/log/`: `sensor.out` / `dashboard.out` (console copy) and `batrade.log` (JSONL, rotated). Alerts append to `var/alerts.log` when the local channel is enabled and the event is warn/crit.

**4. Try the demo without any privileges** (does not touch the network). Stop the sensor first because it shares the database:

```bash
batrade stop
batrade demo
batrade dashboard
```

`demo` seeds the database with synthetic detection scenarios. See *Resetting the database* to clean it up afterwards.

**What to expect on first run:** devices appear in `/devices` after the first sweep (immediately at startup, then every 30 s by default), new-device events are `info` while learning mode is active, and alerts only start once a `warn`/`crit` pattern is detected. Review the inventory and run `batrade approve-baseline` to end learning mode.

## Network auto-detection (Ethernet and Wi-Fi)

The default `config.yaml` needs no editing:

```yaml
network:
  interface: auto   # eth0, enp3s0, wlp2s0, wlan0... chosen at startup
  cidr: auto        # derived from the interface address and netmask
  gateway_ip: null  # taken from the default route
```

Selection order:

1. the interface named in `network.interface`, when set explicitly;
2. the interface carrying the IPv4 default route (unless it is a VPN or virtual bridge);
3. a wired interface with a private IPv4 address, preferring Ethernet over Wi-Fi;
4. any non-virtual interface with IPv4. Docker, libvirt, veth and tailscale bridges are ignored.

`cidr: auto` derives a normalized CIDR (for example `192.168.0.0/24`) from the chosen interface. `gateway_ip: null` adopts the default route only when it belongs to the monitored subnet; otherwise the gateway stays unset and the dashboard says so.

List the interfaces with their kind, address, MAC and whether they carry the default route:

```bash
batrade interfaces
```

```
INTERFAZ      TIPO      ESTADO  IP/CIDR             MAC                RUTA
eth0          ethernet  up      192.168.0.50/24     aa:bb:cc:00:11:33  defecto
wlp2s0        wi-fi     up      10.0.0.20/24        aa:bb:cc:00:11:33
vmnet19       ethernet  up      192.168.150.1/24    aa:bb:cc:00:11:33
lo            loopback  up      127.0.0.1/8         00:00:00:00:00:00
```

To monitor a specific network, set the name explicitly and keep `cidr` automatic:

```yaml
network:
  interface: vmnet19
  cidr: auto
```

For example, `interface: wlp2s0` monitors the wireless LAN even when Ethernet carries the default route; use the wired name (`eth0`, `enp3s0`, `eno1`) when the cable is the network under watch.

Wi-Fi works for discovery and netlink monitoring, but a managed-mode card cannot capture other clients' unicast traffic. Passive sniffing only sees the sensor's own traffic and broadcast/multicast frames; use a wired port mirror or a monitor-mode interface when full packet visibility is required. `doctor` warns when the selected interface is wireless or looks like a hypervisor NIC.

## Sensor modes

| Mode | Requires | Description |
|---|---|---|
| `live` | `CAP_NET_RAW`, `arp-scan` | Passive packet sniffing + active ARP sweep + UDP pass |
| `degraded` | nothing extra | Netlink neighbor table + nmap TCP connect scan (no UDP pass) |
| `replay` | `scapy` | Feeds the detection engine from a recorded `.pcap` file |
| `simulate` | `scapy` | Feeds the engine with built-in synthetic scenarios |
| `auto` | — | Picks `live` or `degraded` based on available capabilities |

## Port scanning, UDP and scheduling

`scan` in `config.yaml` controls both what nmap does and when it runs:

| Key | Default | Effect |
|---|---|---|
| `enabled` | `true` | Enables the scan workers and automatic scheduling |
| `max_concurrent` | `2` | Simultaneous nmap processes; also the per-sweep budget for weekly rescans |
| `timing` | `-T3` | nmap timing template |
| `standard_timeout` | `300` | Process timeout of the `standard` profile (capped at 300 s) |
| `quick_timeout` | `120` | Process timeout of the `quick` profile |
| `udp_timeout` | `60` | `--host-timeout` of the UDP pass (minimum 5); the nmap process gets this plus 30 s |
| `quick_periodic_hours` | `24` | A device whose last scan is older than this gets a `quick` rescan |
| `weekly_rescan_days` | `7` | Trusted (`confiable`) devices get a new `standard` scan after this many days (RF-10) |
| `risky_ports` | 10-port catalogue | `{port, protocol, service, reason}`; `protocol` is mandatory |

Scheduling happens after each sweep: a device seen for the first time gets a `standard` scan; an overdue trusted device gets a new `standard`; anything else overdue gets a `quick`. Weekly rescans are staggered — at most `max_concurrent` per sweep, oldest first — so a network that was offline for a week does not fire a burst of nmap processes. In-flight jobs are coalesced by `(address, profile)`, and the same pair requested from the dashboard cannot be queued twice.

**UDP pass.** The catalogue's UDP ports are scanned with a second, tightly bounded nmap invocation (`-sU -sV --version-light -p U:<catalogue> --host-timeout <scan.udp_timeout>s --max-retries 1`) only when the sensor has `CAP_NET_RAW`. Version detection is what turns an `open|filtered` into `open` when the service answers the probe; only ports reported `open` are stored, because `open|filtered` is the normal outcome for UDP without a reply and would produce false positives. Without raw capture the pass is skipped, the sensor logs the limitation once per scan, and `/health` shows *"UDP no verificable sin CAP_NET_RAW"*. A protocol that was not scanned never marks its known ports as closed.

**Closing ports is a claim, and only `standard`/`vuln` may make it.** `quick` (`-F`) covers roughly the top 100 TCP ports, so its silence about everything else proves nothing: it only opens and updates ports. A port that really disappears is marked `closed` by the next `standard` scan, and if it later comes back, that reappearance is reported again as `port_new` (and `port_risky` for catalogue ports) because a service that returns is news. The trade-off: a genuine closure can take until the next `standard` scan (weekly by default) to be reflected in the panel.

### Verifying UDP detection by hand

This cannot be automated in the test suite: it needs `CAP_NET_RAW`, nmap probing a real device, and a service that actually answers. Do it on the VM with a device that speaks SSDP or mDNS (a smart TV, a printer, a NAS, or the router itself).

1. Confirm the sensor really has raw capture: `batrade doctor` must print `CAP_NET_RAW : sí` and `modo … efectivo: live`.
2. Make sure ports `1900` and `5353` (UDP) are in `scan.risky_ports` — the default catalogue includes both.
3. Trigger a `standard` scan of that device: dashboard → device detail → *Escaneo manual* → `standard`, or `sudo batrade sensor --mode live` and wait for the first sweep.
4. Expected result: a `port_risky` (warn) event in `/events` for that device mentioning `1900/udp` (UPnP/SSDP) or `5353/udp` (mDNS), and the port listed in the device detail with protocol `udp`.
5. If the pass only times out, raise `scan.udp_timeout` and retry. If nmap still reports `open|filtered` for a device you know is answering, that is expected for services that ignore version probes; Batrade deliberately does not turn `open|filtered` into an event.

## Data retention

The sensor purges once an hour, using `sensor.retention_days` (default 90):

- `events` older than the cutoff (`last_ts`);
- finished `scans` rows and their nmap XML files under `paths.scans_dir`;
- `device_history` presence rows;
- `notification_queue` rows already `enviado` or `agotado`.

Pending notifications are never removed: a network outage must not lose alerts. XML files are deleted only after resolving the real path and confirming it stays inside `paths.scans_dir`; a manipulated path or a symlink pointing elsewhere is ignored and logged, and a missing file is tolerated.

## Database schema and migrations

The schema is versioned with `PRAGMA user_version` and an ordered `MIGRATIONS` list in `batrade/db.py`. `SCHEMA_VERSION` is derived from that list, so there is a single source of truth (currently v2). On startup (`init`, `doctor`, sensor, dashboard) only the pending migrations are applied, each one in its own transaction together with the version bump: a migration that fails leaves the schema and the version untouched. Migrations are additive and idempotent.

Before migrating an existing database with data, a backup is written next to it as `<db>.bak-v<N>` with mode `600`; an existing backup is never overwritten (`-2`, `-3`, … are appended). A brand-new database receives every migration and ends at the latest version. `batrade init` and `batrade doctor` print the schema version actually stored in the file.

## Resetting the database

`demo`, `replay` and `simulate` write real rows into the same database as the live sensor, so after a test session the inventory and events are polluted. `reset-db` cleans them:

```bash
sudo batrade stop                      # the sensor must not be running
sudo batrade reset-db                  # asks you to type REINICIAR
sudo batrade reset-db --yes            # non-interactive
sudo batrade reset-db --keep-devices   # keep inventory, wipe events/ports/scans
sudo batrade reset-db --keep-logs      # keep scan XML and var/alerts.log
sudo batrade reset-db --no-backup      # skip the safety copy
```

- **Root only.** The command checks `geteuid() == 0` and refuses otherwise; it does not implement its own password.
- **Sensor stopped.** If a CLI-managed sensor or `batrade-sensor.service` is running it refuses and tells you to stop it first (it never stops it for you).
- **Confirmation.** Without `--yes` it prints what will be deleted (path, size, row counts) and requires typing `REINICIAR`; without a TTY it aborts.
- **Backup by default.** `<db>.bak-reset-<epoch_ms>` with mode 600, created with SQLite's backup API and never overwritten.
- **Scope.** By default every data table is emptied (inventory, history, ports, scans, events, queue, requests, heartbeat, tool status, baseline) and `init` runs again: learning mode back on, no baseline. `--keep-devices` keeps inventory, history and baseline and only clears events/ports/scans/queue/requests/tool status.
- **Artifacts.** Scan XML under `paths.scans_dir` and `var/alerts.log` are cleared too (path containment enforced; symlinks and files outside the directory are ignored).
- **Audit.** The operation is logged in `var/log/batrade.log` with scope, row counts and the invoking user (`SUDO_USER`), never inventory contents.

Exit codes: `0` done, `1` refused or cancelled, `2` invalid arguments or configuration. The reset is **never** exposed in the dashboard and never runs automatically.

## CLI reference

```
batrade <command> [options]

Commands:
  doctor            Check environment capabilities and configuration
  init              Create the database and required directories
  interfaces        List detected IPv4 interfaces (alias: ifaces)
  start             Start sensor and dashboard in the background
  stop              Stop both components
  restart           Restart both components
  status            Show PIDs, heartbeat age, user and effective mode
  sensor            Run the monitoring daemon in the foreground
  dashboard         Serve the web dashboard in the foreground
  demo              Seed the database with demonstration scenarios
  approve-baseline  Mark all current devices as trusted
  reset-db          Wipe data and scan artifacts (root only, sensor stopped)
  export            Export devices, events, or ports as CSV or JSON

Global options:
  --config FILE     Path to config.yaml (default: config.yaml)
  --root DIR        Project root (default: BATRADE_ROOT, else the installed package)
  --version         Print version and exit
```

The root is resolved as `--root` > `BATRADE_ROOT` > the directory of the installed package, so the command works from any working directory. `--system` installs the wrapper in `/usr/local/bin`; `--venv --link` links the venv script into `~/.local/bin`; otherwise use `.venv/bin/batrade` or `python3 -m batrade`.

## Alerts

The sensor supports three notification channels, configured under `notify.channels` in `config.yaml`:

- `local` — enabled by default; appends plain-text alerts to `var/alerts.log`
- `telegram` — sends a message to a Telegram chat; requires `TELEGRAM_TOKEN` and `TELEGRAM_CHAT_ID` in `.env`
- `discord` — posts to a Discord webhook; requires `DISCORD_WEBHOOK` in `.env`

Copy `.env.example` to `.env`, fill in the credentials you want to use, and restrict permissions:

```bash
cp .env.example .env
chmod 600 .env
```

Every alert answers *what happened / why it matters / what to do*, plus event, time, source/destination and accumulated repetitions. A failed delivery never loses the event: it stays queued with backoff and visible in the panel.

## Panel en vivo

El panel ya no necesita recargar para enseñar lo que llega. Cada `dashboard.live_poll_s`
segundos (3 por defecto, rango 1..60) el navegador pide `GET /api/live` —la única ruta
JSON del proyecto y de sólo lectura— y con esa respuesta actualiza los contadores de
*Panel*, la tabla de *Alertas*, el latido del sensor y los avisos emergentes. Sin
WebSockets ni SSE: un `GET` cada pocos segundos.

- **Cursor, no historial.** La primera respuesta sólo trae `max_id`, el resumen y el
  latido; a partir de ahí el cliente pide `?after=<id>`. Abrir o recargar el panel no
  dispara avisos de lo que ya estaba en la base. Las repeticiones deduplicadas no vuelven
  a salir (igual que en las notificaciones del sensor); una escalada de `warn` a `crit`
  sí llega, porque es un evento nuevo con su propio id.
- **Pop-ups.** Hasta cuatro a la vez. Un `crit` se queda hasta que lo cierres; un `warn`
  desaparece a los 10 s. Si en un ciclo llegan más de tres, se agrupan en un solo aviso
  «N alertas nuevas».
- **Sonido.** Web Audio sintetizado, sin archivos ni CDN: un tono para `warn` y un doble
  tono más grave para `crit`, como mucho uno cada 5 s. El interruptor «Avisos» de la
  barra guarda las preferencias (sonido, notificaciones, sólo críticas) en
  `localStorage`.
- **Notificaciones y título.** Con contexto seguro y permiso concedido, cada alerta
  genera una notificación que al pulsarla enfoca la pestaña y abre `/events`; fuera de la
  pestaña el título pasa a `(N) Batrade` y se limpia al volver.

### Límites que conviene conocer

- **El sonido exige un clic.** Los navegadores no permiten audio antes de una
  interacción: hasta que pulses «Avisos» el panel está en silencio. Si la preferencia
  sobrevive a una recarga, el primer clic o tecla de la página vuelve a habilitarlo.
- **Notificaciones sólo en contexto seguro.** `localhost` y `127.0.0.1` cuentan como
  seguros; por HTTP con una IP de la LAN no lo son. En ese caso el aviso se queda en el
  pop-up de la página y la barra explica el motivo (lo mismo si el navegador no admite
  notificaciones o si el permiso está bloqueado).
- **Pestaña cerrada, no hay panel.** El sondeo vive en la página: si cierras la pestaña
  no hay avisos, y con la pestaña oculta el ritmo baja a 15 s mientras las alertas se
  acumulan en el título. Los canales de Telegram y Discord siguen siendo cosa del sensor.
- **Sin conexión.** Si el panel no responde aparece «Sin conexión con el panel» y el
  sondeo retrocede hasta 30 s; al volver el servidor se reanuda solo. Con
  `DASHBOARD_TOKEN` configurado, una sesión caducada detiene el sondeo con un 401: hay
  que volver a iniciar sesión.
- **Qué no se refresca.** En *Dispositivos* el estado en línea no se actualiza en vivo
  (haría falta otra ruta JSON, fuera de alcance) y los contadores de falsos positivos
  quedan como los pintó la última carga.

## Production deployment (systemd)

The `deploy/` directory contains two unit files:

- `batrade-sensor.service` — runs the sensor with `CAP_NET_RAW` and `CAP_NET_ADMIN`
- `batrade-dashboard.service` — serves the Flask dashboard

```bash
sudo bash install.sh --systemd      # from the repository; rewrites paths and ExecStart
```

The installer rewrites `WorkingDirectory`, `ReadWritePaths` and `ExecStart` for the real install path and Python, creates the `batrade` service user when missing, and gives it ownership of `var/`. It does **not** enable the units; do that with `systemctl enable --now batrade-sensor batrade-dashboard`.

`ProtectHome=true` is part of the hardening, so a unit cannot read a project under `/home`: keep the installation outside your home (for example `/opt/batrade`, where `--system` puts it) or use the CLI instead. `--system` alone does not install the units; run `--systemd` afterwards from the installed prefix if you want the service.

**Pick one control plane per installation.** If `batrade-sensor.service` (or the dashboard unit) is active, `batrade start` and `batrade restart` refuse to run and tell you to use `systemctl` or stop the unit first: two sensors over the same database would mean two writers. `status` and `doctor` show the effective user, the real mode and, when `CAP_NET_RAW` is missing, the hint to run with `sudo` for `live`.

## Real test on a VM

This is the recommended path for a first real run.

**VM requirements**

- Any modern Linux from the table above with Python ≥ 3.11.
- A second network adapter in **bridged** mode on the LAN you want to watch, or the host's physical adapter passed through. NAT works but limits visibility: the VM only sees its own traffic, so ARP spoofing aimed at other hosts and most broadcasts are invisible.
- Allow **promiscuous mode** on the virtual switch if it offers that option (VirtualBox: *Promiscuous Mode: Allow All*; VMware: *Promiscuous*); without it the vNIC drops frames not addressed to it.
- 1 vCPU and 512 MB are enough; 2 GB leaves room for `vuln` scans.
- Root or `sudo` inside the VM (needed for `CAP_NET_RAW`, i.e. live mode).

**Install and check**

```bash
sudo bash install.sh --system --install-deps --start
batrade status
batrade doctor          # expects "efectivo: live" and CAP_NET_RAW: sí
batrade interfaces
curl -s http://127.0.0.1:8000/health
```

If `doctor` says `degraded`, the sensor still works (netlink + TCP connect scans) but does not capture packets or scan UDP; run it with `sudo`. With the repository in place and no systemd, `sudo batrade start` is the simplest control plane.

**First-use flow**

1. Let it sweep for a few minutes and open `http://<vm>:8000/devices`.
2. Review the inventory while learning mode is active (new devices are `info`, not alerted).
3. Annotate what you recognize (alias + trust state) and check `/learning` for candidates with random MACs.
4. Run `sudo batrade approve-baseline` once the inventory is complete: from then on new or unauthorized devices alert normally.

**Demo, cleanup and UDP check**

```bash
batrade stop && batrade demo && batrade dashboard   # inspect /events and /devices
batrade stop
sudo batrade reset-db --yes                          # full wipe + restart of the baseline
sudo batrade reset-db --keep-devices                 # keep inventory, drop simulated events
```

Then run the manual UDP check described in *Verifying UDP detection by hand*. This is the one check the automated suite cannot do for you. To remove the installation, see *System-wide installation* (`--uninstall`, `--purge`).

## Troubleshooting

- **`network.interface inexistente`** — run `batrade interfaces` and copy a real name, or leave `interface: auto`.
- **No detection at all** — run `batrade doctor`: without `CAP_NET_RAW` the passive sniffer, `arp-scan` and the UDP pass are unavailable, so the sensor runs in `degraded` mode. For full mode grant the capability (the systemd unit does) or run as root.
- **`start` refuses with a systemctl message** — the systemd unit is active. Use `sudo systemctl restart batrade-sensor` or stop the unit before using the CLI.
- **`reset-db` refuses** — it needs root and a stopped sensor; stop it with `batrade stop` or `systemctl stop`, and rerun with `sudo`.
- **`batrade: command not found` after `--system`** — `/usr/local/bin` is not in `PATH` (sudo often uses `secure_path`); call `/usr/local/bin/batrade` or fix `PATH`.
- **Wi-Fi sees little traffic** — expected in managed mode; see the Wi-Fi note above.
- **`externally-managed-environment` from pip** — use `bash install.sh --venv` or `pip install --user`.
- **Fedora/RHEL with SELinux** — a custom unit runs unconfined by default; if you add a policy, allow read access to the install path and write access to `var/`.
- **No vendor names** — Batrade uses a local OUI file and falls back across the usual nmap, arp-scan and Wireshark locations. Install `nmap` or `arp-scan` to populate it; vendor names are cosmetic.
- **Dashboard shows a stale gateway** — the sensor stores the learned gateway in `network_baseline`; rerun `batrade init` after changing networks.

## Running tests

```bash
pip install -e ".[dev]"    # pytest; on distribution-managed systems use a venv
python3 -m pytest
```

Tests cover the detection engine, rules, inventory, notification queue, store, dashboard routes, the live-panel JSON endpoint and its cursor, configuration, interface auto-detection, migrations, scan scheduling and close policy, UDP parsing, ARP verification, retention, `reset-db`, the installer and project metadata. They run entirely offline and without privileges, using synthetic observations and the fixtures in `fixtures/pcaps/` and `fixtures/nmap/`. CI runs the suite on Python 3.11, 3.12 and 3.13 (`.github/workflows/tests.yml`).

## Project layout

```
batrade/           Python package
  cli.py           Entry point, subcommands and root resolution
  daemon.py        Background start/stop/status; systemd guard
  sensor.py        Monitoring daemon (multi-threaded)
  inventory.py     Device tracking and trust management
  notify.py        Alert dispatch with retry and deduplication
  db.py            Schema, versioned migrations, backups and connections
  store.py         Data access layer (all SQL)
  config.py        Configuration loading and validation
  events.py        Finding persistence helpers
  demo.py          Demo data seeding
  logging_setup.py JSONL logging with rotation
  detect/          Detection subsystem
    engine.py      Rule orchestration and throttling
    rules.py       Stateless detection rules
    state.py       Sliding-window state for the rules
    scenarios.py   Synthetic traffic for tests and demo
    sniffer.py     Passive packet capture (live mode)
    observation.py Normalized packet representation
  net/             Network utilities
    caps.py        Capability detection and mode resolution
    ifaces.py      IPv4 interface discovery (Ethernet/Wi-Fi) and selection
    discovery.py   Host sweep (arp-scan / netlink fallback)
    nmap_scan.py   Port scanning wrapper (TCP and UDP passes)
    neigh.py       Netlink neighbor table reader
    verify.py      Active ARP binding verification
    oui.py         OUI vendor lookup (multi-distro paths)
    iputil.py      IP/MAC normalization helpers
  dashboard/       Flask web dashboard
    app.py         Routes and view logic
    templates/     Jinja2 HTML templates
    static/        CSS
deploy/            systemd units
fixtures/pcaps/    Recorded captures for tests
fixtures/nmap/     Synthetic nmap XML fixtures (UDP pass and version detection)
scripts/           make_fixtures.py (regenerate captures), sync_tree.sh (installer copy)
tests/             pytest suite
.github/           CI workflow (3.11 / 3.12 / 3.13)
config.yaml        Main configuration
install.sh         Multi-distro installer (repository, --system, --uninstall)
.env.example       Secret variable names (values go only in .env)
REPORTE_*.md       Change reports (sanitization, install/VM)
```

## License

No license file is included yet: choosing one is a pending decision of the project owner. Until then, treat the code as all rights reserved.
