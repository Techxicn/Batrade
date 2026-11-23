"""Interfaz de línea de comandos de Batrade.

    python3 -m batrade doctor
    python3 -m batrade init
    python3 -m batrade sensor --mode simulate --scenario mixed
    python3 -m batrade dashboard
    python3 -m batrade approve-baseline
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import logging
import os
import pwd
import sys
import time
from datetime import datetime
from pathlib import Path

from batrade import __version__, db, store
from batrade.config import Config, ConfigError, load
from batrade.logging_setup import setup_logging
from batrade.net import caps as caps_mod
from batrade.net import ifaces
from batrade.net.iputil import default_gateway, ip_in_cidr

log = logging.getLogger("batrade.cli")


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="batrade", description="Batrade Home-SOC")
    p.add_argument("--config", default="config.yaml", help="ruta de config.yaml")
    p.add_argument("--root", default=None,
                   help="raíz del proyecto (por defecto BATRADE_ROOT o el paquete instalado)")
    p.add_argument("--version", action="version", version=f"Batrade {__version__}")
    # Permite escribir `batrade sensor --config ...` además de `batrade --config ... sensor`.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--config", default=argparse.SUPPRESS)
    common.add_argument("--root", default=argparse.SUPPRESS)
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("doctor", parents=[common], help="diagnóstico de entorno y configuración")
    sub.add_parser("init", parents=[common], help="crea la base de datos y los directorios")
    sub.add_parser("interfaces", parents=[common], aliases=["ifaces"],
                   help="lista las interfaces IPv4 (Ethernet/Wi-Fi) detectadas")

    st = sub.add_parser("start", parents=[common],
                        help="arranca sensor y panel en segundo plano")
    st.add_argument("--only", choices=["sensor", "dashboard"], default=None,
                    help="arrancar sólo un componente")
    st.add_argument("--mode", choices=["auto", "live", "degraded"], default=None,
                    help="modo del sensor al arrancar")

    sp = sub.add_parser("stop", parents=[common], help="detiene sensor y panel")
    sp.add_argument("--only", choices=["sensor", "dashboard"], default=None)

    rp = sub.add_parser("restart", parents=[common], help="reinicia sensor y panel")
    rp.add_argument("--only", choices=["sensor", "dashboard"], default=None)

    sub.add_parser("status", parents=[common], help="estado de sensor y panel")

    s = sub.add_parser("sensor", parents=[common], help="ejecuta el demonio de monitoreo")
    s.add_argument("--mode", default=None,
                   choices=["auto", "live", "degraded", "replay", "simulate"])
    s.add_argument("--scenario", default="mixed",
                   help="escenario sintético (arp_spoof, arp_sweep, syn_scan, dhcp_rogue, "
                        "router_reboot, mixed)")
    s.add_argument("--pcap", default=None, help="pcap a reproducir en modo replay")
    s.add_argument("--speed", type=float, default=5.0,
                   help="factor de aceleración del replay (por defecto 5x)")
    s.add_argument("--duration", type=float, default=None,
                   help="segundos antes de detenerse (útil en pruebas)")

    d = sub.add_parser("dashboard", parents=[common], help="sirve el panel web")
    d.add_argument("--host", default=None)
    d.add_argument("--port", type=int, default=None)

    demo = sub.add_parser("demo", parents=[common], help="siembra la base con escenarios de demostración")
    demo.add_argument("--scenarios", default="mixed,router_reboot",
                      help="lista separada por comas")

    ab = sub.add_parser("approve-baseline", parents=[common], help="aprueba el inventario como línea base")
    ab.add_argument("--include-random-mac", action="store_true",
                    help="aprueba también dispositivos con MAC aleatoria (no recomendado)")

    rd = sub.add_parser("reset-db", parents=[common],
                        help="vacía la base de datos y los artefactos (requiere root)")
    rd.add_argument("--keep-devices", action="store_true",
                    help="conserva inventario, historial y línea base")
    rd.add_argument("--keep-logs", action="store_true",
                    help="conserva los XML de escaneo y var/alerts.log")
    rd.add_argument("--no-backup", action="store_true",
                    help="no crea la copia previa <db>.bak-reset-<epoch_ms>")
    rd.add_argument("--yes", "-y", action="store_true",
                    help="no pide confirmación (pensado para automatizar)")

    ex = sub.add_parser("export", parents=[common], help="exporta inventario o eventos")
    ex.add_argument("--what", choices=["devices", "events", "ports"], default="devices")
    ex.add_argument("--format", choices=["csv", "json"], default="csv")
    ex.add_argument("--out", default=None, help="archivo de salida (por defecto stdout)")
    return p


def package_root() -> Path:
    """Directorio que contiene el paquete (la raíz de una instalación normal)."""
    return Path(__file__).resolve().parent.parent


def resolve_root(args) -> Path:
    """Raíz del proyecto: ``--root`` > ``BATRADE_ROOT`` > paquete instalado.

    Sin esto el comando enlazado dependería del directorio desde el que se
    invoca: `batrade doctor` en /tmp leería /tmp/config.yaml.
    """
    explicit = getattr(args, "root", None)
    if explicit:
        return Path(str(explicit)).expanduser().resolve()
    env = (os.environ.get("BATRADE_ROOT") or "").strip()
    if env:
        return Path(env).expanduser().resolve()
    return package_root()


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    try:
        cfg = load(args.config, resolve_root(args))
    except ConfigError as exc:
        print("Configuración inválida:", file=sys.stderr)
        for err in exc.errors:
            print(f"  - {err}", file=sys.stderr)
        return 2

    setup_logging(cfg.paths.log_dir, "batrade")
    handler = {"doctor": cmd_doctor, "init": cmd_init, "sensor": cmd_sensor,
               "dashboard": cmd_dashboard, "demo": cmd_demo,
               "approve-baseline": cmd_approve, "export": cmd_export,
               "interfaces": cmd_interfaces, "ifaces": cmd_interfaces,
               "start": cmd_start, "stop": cmd_stop, "restart": cmd_restart,
               "reset-db": cmd_reset_db,
               "status": cmd_status}[args.command]
    try:
        return int(handler(cfg, args) or 0)
    except KeyboardInterrupt:
        print("\ninterrumpido", file=sys.stderr)
        return 130


# --------------------------------------------------------------------------- #
# Comandos
# --------------------------------------------------------------------------- #
def _human_ms(ms: int) -> str:
    """Fecha y hora legibles de un epoch en milisegundos."""
    try:
        return datetime.fromtimestamp(int(ms) / 1000).strftime("%Y-%m-%d %H:%M:%S")
    except (OverflowError, OSError, ValueError):
        return "fecha inválida"


def _heartbeat_label(hb, stale_after_s: int = 45) -> str:
    """Latido del sensor como fecha, edad y estado (nunca un epoch desnudo)."""
    if hb is None:
        return "nunca"
    ts = int(hb["ts"])
    edad = max(0, (store_now() - ts) // 1000)
    aviso = f"  ·  sin latido reciente (>{stale_after_s} s)" if edad > stale_after_s else ""
    return f"{_human_ms(ts)}  (hace {edad} s){aviso}"


def _capture_label(hb) -> str | None:
    """Estado de captura del último latido en una línea (D-01)."""
    if hb is None or not hb["detalle"]:
        return None
    try:
        captura = json.loads(hb["detalle"]).get("captura")
    except (TypeError, ValueError):
        return None
    if not isinstance(captura, dict):
        return None
    contadores = captura.get("contadores") or {}
    ultima = captura.get("ultima_obs_ts")
    hace = ("sin observaciones" if ultima is None
            else f"última obs. hace {captura.get('idle_s')} s")
    tipos = " ".join(f"{k}={contadores.get(k, 0)}"
                     for k in ("arp", "syn", "dhcp", "neigh"))
    return f"{captura.get('estado', '?')}  ·  {hace}  ·  {tipos}"


def whoami() -> str:
    """Usuario efectivo del proceso, con su uid."""
    uid = os.geteuid()
    try:
        nombre = pwd.getpwuid(uid).pw_name
    except (KeyError, OSError):
        nombre = "desconocido"
    return f"{nombre} (uid {uid})"


def var_owner_warning(var_dir: Path, euid: int | None = None) -> str | None:
    """Avisa si el CLI corre como root sobre un `var/` de otro usuario.

    El CLI lanzado con sudo crea PIDs, logs, XML y copias a nombre de root. No
    se hace `chown` automático (sería invasivo); `doctor` lo advierte para que
    el operador decida entre usar el mismo usuario o arreglar la propiedad.
    """
    euid = os.geteuid() if euid is None else euid
    if euid != 0:
        return None
    try:
        info = Path(var_dir).stat()
    except OSError:
        return None
    if info.st_uid == 0:
        return None
    try:
        dueno = pwd.getpwuid(info.st_uid).pw_name
    except (KeyError, OSError):
        dueno = f"uid {info.st_uid}"
    return (f"var/ pertenece a {dueno} y el CLI corre como root: los archivos nuevos "
            "quedarán a nombre de root (usa el mismo usuario o revisa la propiedad)")


def mode_hint(caps, mode: str) -> str | None:
    """Pista sobre privilegios: qué falta para el modo live."""
    if mode == "live":
        return None
    if not caps.raw_capture:
        return "sin CAP_NET_RAW: modo degradado; para 'live' ejecuta con sudo"
    return None


# Prefijos de MAC típicos de hipervisores: en una VM suelen indicar NAT o
# puente del host, y el sniffer verá menos tráfico del real.
VIRTUAL_MAC_PREFIXES = ("08:00:27", "00:0c:29", "00:50:56", "52:54:00", "00:15:5d")
VIRTUAL_IFACE_HINTS = ("vboxnet", "vmnet", "virbr", "docker", "br-", "veth", "tap",
                       "tun", "lxc", "podman")


def looks_virtual(name: str | None, mac: str | None) -> bool:
    """Heurística: ¿la interfaz parece de hipervisor o contenedor?

    No distingue NAT de puente (no es observable desde dentro), pero avisa de
    que en una VM el adaptador suele ser virtual y conviene revisar el modo.
    """
    nombre = (name or "").lower()
    if any(nombre.startswith(p) for p in VIRTUAL_IFACE_HINTS):
        return True
    return (mac or "").lower().startswith(VIRTUAL_MAC_PREFIXES)


def vm_probe_lines(cfg: Config, caps, mode: str) -> list[str]:
    """Líneas informativas del bloque «Prueba en VM» de `doctor`."""
    info = ifaces.find(cfg.network.interface) if cfg.network.interface else None
    mac = info.mac if info else None
    virtual = looks_virtual(cfg.network.interface, mac)
    detalle = "sí (hipervisor: NAT o puente)" if virtual else "no"
    pista = ("sin CAP_NET_RAW: para 'live' ejecuta el sensor con sudo"
             if not caps.raw_capture else "listo para modo live")
    return [
        f"modo {mode} · CAP_NET_RAW {'sí' if caps.raw_capture else 'NO'} · "
        f"interfaz virtual/NAT: {detalle}",
        f"{cfg.network.interface or '(sin interfaz)'} · subred {cfg.network.cidr} · {pista}",
    ]


def cmd_doctor(cfg: Config, _args) -> int:
    caps = caps_mod.probe()
    mode, notes = caps_mod.resolve_mode(cfg.sensor.mode, caps)
    conn = db.initialize(cfg.paths.db)
    rows = store.count_devices(conn)
    hb = store.get_heartbeat(conn, "sensor")
    info = ifaces.find(cfg.network.interface) if cfg.network.interface else None

    print(f"Batrade {__version__}  ·  {cfg.root}")
    origen = "autodetectada" if cfg.interface_auto else "fijada"
    detalle = f"{info.address()}, {info.kind}" if info else "sin IPv4"
    print(f"  interfaz        : {cfg.network.interface or '(ninguna)'} "
          f"({origen}; {detalle})")
    print(f"  subred          : {cfg.network.cidr}"
          f"{'  (derivada)' if cfg.cidr_auto else ''}")
    print(f"  gateway         : {cfg.network.gateway_ip or default_gateway() or 'desconocido'}")
    print(f"  modo solicitado : {cfg.sensor.mode}  ->  efectivo: {mode}")
    print(f"  ejecutando como : {whoami()}")
    print(f"  CAP_NET_RAW     : {'sí' if caps.raw_capture else 'NO'}")
    print(f"  arp-scan        : {'sí' if caps.arp_scan else 'NO'}   "
          f"nmap: {'sí' if caps.nmap else 'NO'}   "
          f"iproute2: {'sí' if caps.iproute else 'NO'}")
    print(f"  netlink vecinos : {'sí' if caps.netlink_neigh else 'NO'}   "
          f"scapy: {'sí' if caps.scapy else 'NO'}   "
          f"tshark: {'sí' if caps.tshark else 'NO'}")
    version = db.user_version(conn)
    pendiente = "" if version == db.SCHEMA_VERSION else f" (pendiente v{db.SCHEMA_VERSION})"
    print(f"  base de datos   : {cfg.paths.db}  schema v{version}{pendiente}")
    print(f"  dispositivos    : {rows.get('total', 0)} "
          f"(en línea {rows.get('online', 0)}, desconocidos {rows.get('desconocidos', 0)})")
    print(f"  heartbeat       : {_heartbeat_label(hb, cfg.sensor.heartbeat_interval * 3)}")
    captura = _capture_label(hb)
    if captura:
        print(f"  captura         : {captura}")
    pista = mode_hint(caps, mode)
    if pista:
        print(f"  pista           : {pista}")
    aviso_var = var_owner_warning(cfg.paths.db.parent)
    if aviso_var:
        print(f"  aviso           : {aviso_var}")
    for note in cfg.warnings:
        print(f"  aviso           : {note}")
    for note in notes:
        print(f"  modo            : {note}")
    for reason in caps.reasons:
        print(f"  limitación      : {reason}")
    lineas_vm = vm_probe_lines(cfg, caps, mode)
    for i, linea in enumerate(lineas_vm):
        etiqueta = "prueba en VM" if i == 0 else ""
        print(f"  {etiqueta:<16}: {linea}")
    print("\nConsejo: `python3 -m batrade demo` puebla el panel sin privilegios.")
    return 0


def cmd_interfaces(cfg: Config, _args) -> int:
    rows = ifaces.list_ipv4(include_loopback=True)
    default = ifaces.default_iface()
    print(f"Batrade {__version__} · interfaces IPv4 de este host\n")
    if not rows:
        print("  No se detectó ninguna interfaz IPv4 (¿iproute2 instalado?).")
        return 1
    print(f"  {'INTERFAZ':<14}{'TIPO':<10}{'ESTADO':<8}{'IP/CIDR':<20}{'MAC':<19}RUTA")
    for info in sorted(rows, key=lambda r: (r.loopback, r.name)):
        ruta = "defecto" if info.name == default else ""
        estado = "up" if info.up else "down"
        print(f"  {info.name:<14}{info.kind:<10}{estado:<8}{info.address():<20}"
              f"{(info.mac or '—'):<19}{ruta}")
    actual = cfg.network.interface or "auto"
    print(f"\n  Config actual: interface={actual}  cidr={cfg.network.cidr}  "
          f"gateway={cfg.network.gateway_ip or 'auto'}")
    print("  La selección automática usa la ruta por defecto y prefiere cable.")
    print("  Para fijar una interfaz: network.interface: <INTERFAZ> "
          "(y network.cidr: auto).")
    return 0


# --------------------------------------------------------------------------- #
# Control del servicio (start/stop/restart/status)
# --------------------------------------------------------------------------- #
def _config_file(args) -> Path:
    """Ruta absoluta del config.yaml con la que arrancar los hijos."""
    path = Path(args.config)
    if not path.is_absolute():
        path = resolve_root(args) / path
    return path.resolve()


def cmd_start(cfg: Config, args) -> int:
    from batrade.daemon import DaemonError, start_component

    targets = [args.only] if args.only else ["sensor", "dashboard"]
    config_file = _config_file(args)
    for name in targets:
        mode = getattr(args, "mode", None) if name == "sensor" else None
        try:
            _info, message = start_component(cfg, config_file, name, mode)
        except DaemonError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1
        print(message)
    print(f"Panel: http://{cfg.dashboard.host}:{cfg.dashboard.port}")
    print(f"Estado: {sys.executable} -m batrade status")
    print(f"Parar : {sys.executable} -m batrade stop")
    return 0


def cmd_stop(cfg: Config, args) -> int:
    from batrade.daemon import stop_component

    targets = [args.only] if args.only else ["dashboard", "sensor"]
    for name in targets:
        _info, message = stop_component(cfg, name)
        print(message)
    return 0


def cmd_restart(cfg: Config, args) -> int:
    from batrade.daemon import DaemonError, start_component, stop_component

    targets = [args.only] if args.only else ["sensor", "dashboard"]
    for name in reversed(targets):
        print(stop_component(cfg, name)[1])
    time.sleep(0.3)
    config_file = _config_file(args)
    for name in targets:
        try:
            _info, message = start_component(cfg, config_file, name)
        except DaemonError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1
        print(message)
    print(f"Panel: http://{cfg.dashboard.host}:{cfg.dashboard.port}")
    return 0


def cmd_status(cfg: Config, _args) -> int:
    from batrade.daemon import status_all

    caps = caps_mod.probe()
    mode, notes = caps_mod.resolve_mode(cfg.sensor.mode, caps)
    for info in status_all(cfg):
        print(f"  {info.name:<10} {info.state()}")
        print(f"  {'':<10} log: {info.logfile}")
    age: int | None = None
    hb = None
    try:
        conn = db.connect(cfg.paths.db, readonly=True)
        try:
            hb = store.get_heartbeat(conn, "sensor")
        finally:
            conn.close()
        if hb is not None:
            age = max(0, (store_now() - int(hb["ts"])) // 1000)
    except Exception:  # base inexistente o aún sin latido
        age = None
    print(f"  {'latido':<10} {'sin datos' if age is None else f'hace {age} s'}")
    captura = _capture_label(hb)
    if captura:
        print(f"  {'captura':<10} {captura}")
    print(f"  {'usuario':<10} {whoami()}")
    print(f"  {'modo':<10} {mode}")
    for note in notes:
        print(f"  {'':<10} {note}")
    pista = mode_hint(caps, mode)
    if pista:
        print(f"  {'':<10} {pista}")
    print(f"  {'panel':<10} http://{cfg.dashboard.host}:{cfg.dashboard.port}")
    return 0


def cmd_init(cfg: Config, _args) -> int:
    conn = db.initialize(cfg.paths.db)
    gw = _init_meta(conn, cfg)
    print(f"Base de datos lista en {cfg.paths.db}  ·  schema v{db.user_version(conn)}")
    print(f"Interfaz vigilada: {cfg.network.interface or '(ninguna)'}  ·  "
          f"subred {cfg.network.cidr}  ·  gateway {gw or 'sin definir'}")
    print(f"Directorio de escaneos: {cfg.paths.scans_dir}")
    print("Siguiente paso: `python3 -m batrade sensor --mode degraded` y "
          "`python3 -m batrade dashboard` en otra terminal.")
    return 0


def _init_meta(conn, cfg: Config) -> str | None:
    """Metadatos de línea base que deja `init`; también los usa `reset-db`."""
    ts = store_now()
    gw = cfg.network.gateway_ip or default_gateway()
    if gw and not ip_in_cidr(gw, cfg.network.cidr):
        print(f"  aviso: gateway {gw} fuera de {cfg.network.cidr}; no se guarda")
        gw = None
    if gw:
        store.set_meta(conn, "gateway_ip", gw, ts)
    store.set_meta(conn, "sensor_mode", cfg.sensor.mode, ts)
    store.set_meta(conn, "interface", cfg.network.interface, ts)
    return gw


# --------------------------------------------------------------------------- #
# reset-db: acción manual, explícita y sólo CLI (nunca en el panel)
# --------------------------------------------------------------------------- #
RESET_WORD = "REINICIAR"


def _confirm_reset(assume_yes: bool) -> bool:
    """Exige escribir REINICIAR; sin TTY aborta en vez de adivinar."""
    if assume_yes:
        return True
    if not sys.stdin.isatty():
        print("Sin terminal interactiva: repite con --yes para confirmar", file=sys.stderr)
        return False
    try:
        respuesta = input(f"Escribe {RESET_WORD} para continuar: ")
    except EOFError:
        return False
    return respuesta.strip() == RESET_WORD


def cmd_reset_db(cfg: Config, args) -> int:
    """Vacía la base y los artefactos de pruebas. Requiere root y sensor parado."""
    from batrade import daemon
    from batrade.sensor import safe_unlink_scan

    if os.geteuid() != 0:
        print("reset-db requiere privilegios de administrador: ejecuta con sudo",
              file=sys.stderr)
        return 1

    # El sensor es el único escritor: con él vivo no se toca la base.
    sensor_activo = (daemon.pid_of(cfg, "sensor") is not None
                     or daemon.systemd_unit_active("batrade-sensor.service"))
    if sensor_activo:
        print("El sensor está en ejecución: deténlo antes con 'batrade stop' o "
              "'sudo systemctl stop batrade-sensor' y repite el reset.", file=sys.stderr)
        return 1

    if not cfg.paths.db.exists():
        print(f"No hay base de datos en {cfg.paths.db}; nada que reiniciar.")
        return 0

    keep_devices = bool(getattr(args, "keep_devices", False))
    keep_logs = bool(getattr(args, "keep_logs", False))
    no_backup = bool(getattr(args, "no_backup", False))
    assume_yes = bool(getattr(args, "yes", False))

    conn = db.connect(cfg.paths.db)
    try:
        counts = store.table_counts(conn)
        try:
            tamano = cfg.paths.db.stat().st_size / 1024
        except OSError:
            tamano = 0.0
        print("Se va a reiniciar la base de datos:")
        print(f"  ruta         : {cfg.paths.db}")
        print(f"  tamaño       : {tamano:.1f} KiB")
        print(f"  alcance      : {'inventario conservado' if keep_devices else 'borrado completo'}")
        print(f"  se borran    : {counts.get('events', 0)} eventos, "
              f"{counts.get('ports', 0)} puertos, {counts.get('scans', 0)} escaneos, "
              f"{counts.get('notification_queue', 0)} notificaciones")
        if keep_devices:
            print(f"  se conservan : {counts.get('devices', 0)} dispositivos y su historial")
        else:
            print(f"  se borran    : {counts.get('devices', 0)} dispositivos y la línea base")
        print(f"  copia previa : "
              f"{'(omitida por --no-backup)' if no_backup else f'{cfg.paths.db.name}.bak-reset-<epoch_ms>'}")
        print(f"  artefactos   : "
              f"{'conservados (--keep-logs)' if keep_logs else 'XML de escaneo y alerts.log'}")

        if not _confirm_reset(assume_yes):
            print("reset cancelado: no se ha modificado nada", file=sys.stderr)
            return 1

        copia = None
        if not no_backup:
            copia = db.backup_tagged(conn, f"reset-{store_now()}")
        filas = (store.reset_keep_devices if keep_devices else store.reset_all)(conn)
        store.vacuum(conn)
        gw = None
        if not keep_devices:
            # Misma lógica que `init`: sin línea base, aprendizaje activo.
            gw = _init_meta(conn, cfg)
    finally:
        conn.close()

    xml_borrados = 0
    xml_ignorados = 0
    alerts_vaciado = False
    if not keep_logs:
        try:
            candidatos = sorted(cfg.paths.scans_dir.glob("*.xml"))
        except OSError:
            candidatos = []
        for xml in candidatos:
            if safe_unlink_scan(cfg.paths.scans_dir, xml):
                xml_borrados += 1
            else:
                xml_ignorados += 1
        if cfg.paths.alerts_log.exists():
            try:
                cfg.paths.alerts_log.write_text("", encoding="utf-8")
                cfg.paths.alerts_log.chmod(0o600)
                alerts_vaciado = True
            except OSError as exc:
                print(f"  aviso: no se pudo vaciar {cfg.paths.alerts_log.name}: {exc}",
                      file=sys.stderr)

    print("Base reiniciada.")
    check = db.connect(cfg.paths.db, readonly=True)
    try:
        version = db.user_version(check)
    finally:
        check.close()
    print(f"  filas borradas: {sum(filas.values())}  ·  schema v{version}")
    if copia is not None:
        print(f"  copia         : {copia.name} (permisos 600)")
    if not keep_logs:
        print(f"  XML borrados  : {xml_borrados}"
              + (f" (ignorados: {xml_ignorados})" if xml_ignorados else ""))
        if alerts_vaciado:
            print("  alerts.log    : vaciado")
    if not keep_devices:
        print(f"  línea base    : reiniciada (aprendizaje activo, "
              f"gateway {gw or 'sin definir'})")

    log.info("reset-db", extra={"fields": {
        "alcance": "keep-devices" if keep_devices else "completo",
        "filas": filas,
        "backup": copia.name if copia else None,
        "xml": xml_borrados,
        "usuario": os.environ.get("SUDO_USER") or whoami(),
    }})
    return 0


def cmd_sensor(cfg: Config, args) -> int:
    from batrade.sensor import Sensor, cli_signal_handlers

    mode = args.mode or cfg.sensor.mode
    sensor = Sensor(cfg, mode, scenario=args.scenario, pcap=args.pcap,
                    speed=args.speed, duration=args.duration)
    print(f"batrade-sensor en modo {sensor.mode} · {cfg.network.cidr} sobre "
          f"{cfg.network.interface or '(sin interfaz)'}")
    for note in cfg.warnings:
        print(f"  red: {note}")
    for note in sensor.mode_notes:
        print(f"  aviso: {note}")
    if sensor.mode in ("replay", "simulate"):
        print(f"  alimentando motor desde "
              f"{args.pcap or args.scenario} a {args.speed}x")
    cli_signal_handlers(sensor.stop_event)
    sensor.run()
    return 0


def cmd_dashboard(cfg: Config, args) -> int:
    from batrade.dashboard.app import create_app

    host = args.host or cfg.dashboard.host
    port = args.port or cfg.dashboard.port
    app = create_app(cfg)
    print(f"Panel en http://{host}:{port}  (Ctrl+C para detener)")
    if host not in ("127.0.0.1", "localhost", "::1") and not cfg.dashboard.auth_token:
        print("  ADVERTENCIA: expuesto fuera de loopback sin DASHBOARD_TOKEN", file=sys.stderr)
    app.run(host=host, port=port, debug=False, use_reloader=False, threaded=True)
    return 0


def cmd_demo(cfg: Config, args) -> int:
    from batrade.demo import seed_demo

    names = [s.strip() for s in args.scenarios.split(",") if s.strip()]
    final = seed_demo(cfg, names)
    print("Datos de demostración cargados:")
    for k, v in final.items():
        print(f"  {k:<14}: {v}")
    print("\nAbre el panel con: python3 -m batrade dashboard")
    return 0


def cmd_approve(cfg: Config, args) -> int:
    from batrade.inventory import approve_baseline

    conn = db.initialize(cfg.paths.db)
    result = approve_baseline(conn, include_random_mac=args.include_random_mac)
    print(f"Aprobados como confiables: {result['aprobados']}")
    print(f"Quedan en revisión        : {result['pendientes']}")
    return 0


def cmd_export(cfg: Config, args) -> int:
    conn = db.connect(cfg.paths.db, readonly=True)
    if args.what == "devices":
        rows = [dict(r) for r in conn.execute(
            "SELECT id, mac, ip_actual, fabricante, hostname, alias, estado_confianza, "
            "mac_aleatoria, first_seen, last_seen, en_linea FROM devices ORDER BY id")]
    elif args.what == "ports":
        rows = [dict(r) for r in conn.execute(
            "SELECT device_id, protocolo, puerto, estado, servicio, version, riesgoso, "
            "first_seen, last_seen FROM ports ORDER BY device_id, puerto")]
    else:
        rows = [dict(r) for r in conn.execute(
            "SELECT id, ts, severidad, tipo, ip_origen, mac_origen, ip_destino, "
            "repeat_count, disposicion, notificado FROM events ORDER BY ts DESC")]
    conn.close()

    if args.format == "json":
        payload = json.dumps(rows, ensure_ascii=False, indent=2, default=str)
    else:
        buf = io.StringIO()
        if rows:
            writer = csv.DictWriter(buf, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)
        payload = buf.getvalue()

    if args.out:
        Path(args.out).write_text(payload, encoding="utf-8")
        print(f"Exportadas {len(rows)} filas a {args.out}")
    else:
        print(payload)
    return 0


def store_now() -> int:
    from batrade.net.iputil import now_ms
    return now_ms()
