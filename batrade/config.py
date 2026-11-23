"""Carga y validación de config.yaml + .env.

Todo lo configurable vive aquí; nada está hardcodeado en el código fuente (RNF-03).
Los secretos se resuelven por nombre de variable de entorno, nunca del YAML.
"""
from __future__ import annotations

import ipaddress
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from batrade.net import ifaces
from batrade.net.iputil import default_gateway, valid_ipv4

log = logging.getLogger("batrade.config")


class ConfigError(Exception):
    """Error de configuración con todos los problemas detectados."""

    def __init__(self, errors: list[str]):
        self.errors = list(errors)
        super().__init__("; ".join(self.errors))


# --------------------------------------------------------------------------- #
# Secciones
# --------------------------------------------------------------------------- #
@dataclass(slots=True)
class NetworkCfg:
    interface: str = "eth0"
    cidr: str = "192.168.1.0/24"
    gateway_ip: str | None = None
    dhcp_server_ip: str | None = None


@dataclass(slots=True)
class SensorCfg:
    mode: str = "auto"
    sweep_interval: int = 30
    presence_misses: int = 3
    heartbeat_interval: int = 15
    retention_days: int = 90
    neighbor_watch: bool = True
    # Segundos sin ninguna observación en modo live antes de avisar en /health.
    capture_idle_warn_s: int = 600


@dataclass(frozen=True, slots=True)
class RiskyPort:
    port: int
    protocol: str
    service: str
    reason: str


@dataclass(slots=True)
class ScanCfg:
    enabled: bool = True
    max_concurrent: int = 2
    timing: str = "-T3"
    standard_timeout: int = 300
    quick_timeout: int = 120
    udp_timeout: int = 60
    quick_periodic_hours: int = 24
    weekly_rescan_days: int = 7
    # Objetivos que no se escanean nunca: IPs sueltas o redes CIDR. Sirve para
    # equipos que no responden y sólo dejarían XML a medias en cada intento.
    exclude: tuple[str, ...] = ()
    risky_ports: dict[tuple[str, int], RiskyPort] = field(default_factory=dict)


@dataclass(slots=True)
class DetectCfg:
    window_s: int = 10
    syn_ports_warn: int = 15
    syn_ports_crit: int = 100
    syn_dsts_crit: int = 25
    arp_sweep_ips: int = 30
    arp_verify: bool = True
    arp_verify_timeout: float = 1.5
    arp_exceptions: tuple[str, ...] = ()
    cooldown_s: int = 300


@dataclass(slots=True)
class NotifyCfg:
    channels: list[dict[str, Any]] = field(default_factory=lambda: [{"type": "local"}])
    timeout_s: float = 8.0
    max_attempts: int = 8


@dataclass(slots=True)
class DashboardCfg:
    host: str = "127.0.0.1"
    port: int = 8000
    auth_token: str | None = None
    # Cadencia del sondeo de /api/live que hace el panel en vivo (segundos).
    live_poll_s: int = 3


@dataclass(slots=True)
class PathsCfg:
    db: Path = Path("var/batrade.db")
    scans_dir: Path = Path("var/scans")
    log_dir: Path = Path("var/log")
    alerts_log: Path = Path("var/alerts.log")
    oui_file: Path = Path("/usr/share/nmap/nmap-mac-prefixes")


@dataclass(slots=True)
class Config:
    root: Path
    network: NetworkCfg = field(default_factory=NetworkCfg)
    sensor: SensorCfg = field(default_factory=SensorCfg)
    scan: ScanCfg = field(default_factory=ScanCfg)
    detect: DetectCfg = field(default_factory=DetectCfg)
    notify: NotifyCfg = field(default_factory=NotifyCfg)
    dashboard: DashboardCfg = field(default_factory=DashboardCfg)
    paths: PathsCfg = field(default_factory=PathsCfg)
    # Interfaz/subred resueltas automáticamente y avisos para el operador.
    interface_auto: bool = False
    cidr_auto: bool = False
    warnings: list[str] = field(default_factory=list)

    @property
    def network_obj(self) -> ipaddress.IPv4Network:
        return ipaddress.IPv4Network(self.network.cidr, strict=False)

    def ensure_dirs(self) -> None:
        for d in (self.paths.db.parent, self.paths.scans_dir, self.paths.log_dir,
                  self.paths.alerts_log.parent):
            d.mkdir(parents=True, exist_ok=True)


# --------------------------------------------------------------------------- #
# .env
# --------------------------------------------------------------------------- #
def load_dotenv(path: Path) -> dict[str, str]:
    """Parser mínimo de .env. No sobreescribe variables ya presentes en el entorno.

    Un `.env` ilegible no puede tumbar el arranque: en una instalación systemd
    el fichero puede pertenecer a otro usuario. Se avisa y se sigue sin él.
    """
    values: dict[str, str] = {}
    if not path.exists():
        return values
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        log.warning("no se pudo leer %s: %s", path, exc)
        return values
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip().strip('"').strip("'")
        if not key:
            continue
        values[key] = val
        os.environ.setdefault(key, val)
    return values


# --------------------------------------------------------------------------- #
# Carga
# --------------------------------------------------------------------------- #
def _get(section: dict[str, Any], key: str, default: Any) -> Any:
    val = section.get(key, default)
    return default if val is None else val


def _parse_risky(raw: Any, errors: list[str]) -> dict[tuple[str, int], RiskyPort]:
    out: dict[tuple[str, int], RiskyPort] = {}
    if not isinstance(raw, list):
        errors.append("scan.risky_ports debe ser una lista de objetos")
        return out
    for item in raw:
        if not isinstance(item, dict):
            errors.append(f"scan.risky_ports: entrada inválida {item!r}")
            continue
        try:
            port = int(item["port"])
            proto = str(item.get("protocol", "tcp")).lower()
        except (KeyError, TypeError, ValueError):
            errors.append(f"scan.risky_ports: entrada sin port/protocol válido: {item!r}")
            continue
        if not 1 <= port <= 65535:
            errors.append(f"scan.risky_ports: puerto fuera de rango: {port}")
            continue
        if proto not in ("tcp", "udp"):
            errors.append(f"scan.risky_ports: protocolo inválido {proto!r} en puerto {port}")
            continue
        out[(proto, port)] = RiskyPort(
            port=port,
            protocol=proto,
            service=str(item.get("service") or f"{proto}/{port}"),
            reason=str(item.get("reason") or "Servicio considerado riesgoso"),
        )
    return out


def _parse_exclude(raw: Any, errors: list[str]) -> tuple[str, ...]:
    """Normaliza ``scan.exclude``: IPv4 sueltas o redes CIDR normalizadas.

    Se valida al cargar para que un typo no deje un objetivo «excluido» que en
    realidad se sigue escaneando: es la vía que ofrece el mensaje de /health.
    """
    if not isinstance(raw, list):
        errors.append("scan.exclude debe ser una lista de IPs o redes CIDR")
        return ()
    out: list[str] = []
    for item in raw:
        texto = str(item).strip()
        ip = valid_ipv4(texto)
        if ip:
            out.append(ip)
            continue
        try:
            red = ipaddress.IPv4Network(texto, strict=False)
        except ValueError:
            errors.append(f"scan.exclude: {item!r} no es una IP ni una red IPv4")
            continue
        out.append(str(red))
    return tuple(dict.fromkeys(out))


def load_config(path: str | Path = "config.yaml", root: str | Path | None = None) -> Config:
    """Carga config.yaml y valida todo lo que puede romper el arranque."""
    cfg_path = Path(path)
    if not cfg_path.is_absolute():
        cfg_path = Path(root or Path.cwd()) / cfg_path
    if not cfg_path.exists():
        raise ConfigError([f"No existe el archivo de configuración: {cfg_path}"])

    try:
        raw_config = cfg_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError([f"No se pudo leer {cfg_path}: {exc}"]) from exc

    try:
        data = yaml.safe_load(raw_config) or {}
    except yaml.YAMLError as exc:
        raise ConfigError([f"YAML inválido en {cfg_path}: {exc}"]) from exc
    if not isinstance(data, dict):
        raise ConfigError([f"{cfg_path} debe contener un mapa en la raíz"])

    base = Path(root or cfg_path.parent).resolve()
    errors: list[str] = []

    net_raw = data.get("network") or {}
    sen_raw = data.get("sensor") or {}
    scan_raw = data.get("scan") or {}
    det_raw = data.get("detect") or {}
    not_raw = data.get("notify") or {}
    dash_raw = data.get("dashboard") or {}
    path_raw = data.get("paths") or {}

    mode = str(_get(sen_raw, "mode", "auto")).lower()
    warnings: list[str] = []
    info: ifaces.IfaceInfo | None = None

    # ------------------------------------------------------- interfaz/subred
    # ``auto`` permite arrancar en cualquier equipo (Ethernet o Wi-Fi) sin
    # editar el YAML: se elige la interfaz de la ruta por defecto.
    requested_iface = str(_get(net_raw, "interface", "auto")).strip()
    requested_cidr = str(_get(net_raw, "cidr", "auto")).strip()
    interface_auto = requested_iface.lower() in ifaces.AUTO_VALUES
    cidr_auto = requested_cidr.lower() in ifaces.AUTO_VALUES

    if interface_auto:
        info, reason = ifaces.pick(None)
        if info is None:
            interface = ""
            if mode in ("replay", "simulate"):
                warnings.append(
                    f"sin interfaz IPv4 autodetectable; el modo {mode} no necesita red real"
                )
            else:
                errors.append(
                    "no se pudo autodetectar una interfaz IPv4; define network.interface "
                    "con un nombre real (ver `python3 -m batrade interfaces`)"
                )
        else:
            interface = info.name
            warnings.append(f"interfaz autodetectada: {info.name} ({info.kind}) — {reason}")
            if info.wireless:
                warnings.append(
                    "interfaz Wi-Fi: la captura pasiva sólo verá el tráfico del propio "
                    "equipo; el barrido ARP y netlink siguen funcionando (para ver todo "
                    "el tráfico usa un puerto espejo)"
                )
    else:
        interface = requested_iface
        info = ifaces.find(interface)
        if info is None:
            errors.append(f"network.interface inexistente en este sistema: {interface}")

    if cidr_auto:
        derived = info.cidr if info is not None else None
        if derived:
            cidr = derived
            warnings.append(f"subred derivada de {interface}: {cidr}")
        else:
            cidr = "192.168.1.0/24"
            if mode in ("replay", "simulate"):
                warnings.append(
                    f"sin IPv4 para derivar la subred; se usa {cidr} para la simulación"
                )
            elif info is not None or interface_auto:
                errors.append(
                    f"network.cidr=auto pero {interface or 'la interfaz'} no tiene IPv4"
                )
    else:
        cidr = requested_cidr

    gateway_ip = net_raw.get("gateway_ip") or None
    if gateway_ip is None and mode in ("auto", "live", "degraded"):
        auto_gw = default_gateway()
        if auto_gw:
            try:
                inside = ipaddress.IPv4Address(auto_gw) in ipaddress.IPv4Network(cidr, strict=False)
            except ValueError:
                inside = False
            if inside:
                gateway_ip = auto_gw
                warnings.append(f"gateway autodetectado: {auto_gw}")
            else:
                warnings.append(
                    f"la ruta por defecto apunta a {auto_gw}, fuera de {cidr}; se deja sin "
                    "gateway hasta que definas network.gateway_ip"
                )

    network = NetworkCfg(
        interface=interface,
        cidr=cidr,
        gateway_ip=gateway_ip,
        dhcp_server_ip=net_raw.get("dhcp_server_ip"),
    )
    # Si el YAML trae un gateway vacío, _get ya lo habría dejado en None.
    if network.gateway_ip in ("", "null", "None"):
        network.gateway_ip = None
    if network.dhcp_server_ip in ("", "null", "None"):
        network.dhcp_server_ip = None
    sensor = SensorCfg(
        mode=mode,
        sweep_interval=int(_get(sen_raw, "sweep_interval", 30)),
        presence_misses=int(_get(sen_raw, "presence_misses", 3)),
        heartbeat_interval=int(_get(sen_raw, "heartbeat_interval", 15)),
        retention_days=int(_get(sen_raw, "retention_days", 90)),
        neighbor_watch=bool(_get(sen_raw, "neighbor_watch", True)),
        capture_idle_warn_s=int(_get(sen_raw, "capture_idle_warn_s", 600)),
    )
    detect = DetectCfg(
        window_s=int(_get(det_raw, "window_s", 10)),
        syn_ports_warn=int(_get(det_raw, "syn_ports_warn", 15)),
        syn_ports_crit=int(_get(det_raw, "syn_ports_crit", 100)),
        syn_dsts_crit=int(_get(det_raw, "syn_dsts_crit", 25)),
        arp_sweep_ips=int(_get(det_raw, "arp_sweep_ips", 30)),
        arp_verify=bool(_get(det_raw, "arp_verify", True)),
        arp_verify_timeout=float(_get(det_raw, "arp_verify_timeout", 1.5)),
        arp_exceptions=tuple(str(m).lower() for m in (det_raw.get("arp_exceptions") or [])),
        cooldown_s=int(_get(det_raw, "cooldown_s", 300)),
    )
    scan = ScanCfg(
        enabled=bool(_get(scan_raw, "enabled", True)),
        max_concurrent=max(1, int(_get(scan_raw, "max_concurrent", 2))),
        timing=str(_get(scan_raw, "timing", "-T3")),
        standard_timeout=int(_get(scan_raw, "standard_timeout", 300)),
        quick_timeout=int(_get(scan_raw, "quick_timeout", 120)),
        udp_timeout=int(_get(scan_raw, "udp_timeout", 60)),
        quick_periodic_hours=int(_get(scan_raw, "quick_periodic_hours", 24)),
        weekly_rescan_days=int(_get(scan_raw, "weekly_rescan_days", 7)),
        exclude=_parse_exclude(scan_raw.get("exclude") or [], errors),
        risky_ports=_parse_risky(scan_raw.get("risky_ports") or [], errors),
    )
    notify = NotifyCfg(
        channels=list(not_raw.get("channels") or [{"type": "local"}]),
        timeout_s=float(_get(not_raw, "timeout_s", 8)),
        max_attempts=max(1, int(_get(not_raw, "max_attempts", 8))),
    )
    token_env = str(_get(dash_raw, "auth_token_env", "DASHBOARD_TOKEN"))
    dashboard = DashboardCfg(
        host=str(_get(dash_raw, "host", "127.0.0.1")),
        port=int(_get(dash_raw, "port", 8000)),
        auth_token=os.environ.get(token_env) or None,
        live_poll_s=int(_get(dash_raw, "live_poll_s", 3)),
    )

    def _path(key: str, default: str) -> Path:
        p = Path(str(_get(path_raw, key, default)))
        return p if p.is_absolute() else (base / p)

    paths = PathsCfg(
        db=_path("db", "var/batrade.db"),
        scans_dir=_path("scans_dir", "var/scans"),
        log_dir=_path("log_dir", "var/log"),
        alerts_log=_path("alerts_log", "var/alerts.log"),
        oui_file=_path("oui_file", "/usr/share/nmap/nmap-mac-prefixes"),
    )

    # ---------------------------------------------------------------- checks
    if sensor.mode not in ("auto", "live", "degraded", "replay", "simulate"):
        errors.append(f"sensor.mode inválido: {sensor.mode!r}")

    try:
        net = ipaddress.IPv4Network(network.cidr, strict=False)
        if not 16 <= net.prefixlen <= 30:
            errors.append(
                f"network.cidr fuera de alcance MVP (/{net.prefixlen}); usar /16../30, "
                "recomendado /24"
            )
        if str(net) != network.cidr:
            errors.append(
                f"network.cidr no está normalizado: {network.cidr!r} debería ser {str(net)!r}"
            )
    except ValueError as exc:
        errors.append(f"network.cidr inválido: {exc}")
        net = None

    for label, ip in (("network.gateway_ip", network.gateway_ip),
                      ("network.dhcp_server_ip", network.dhcp_server_ip)):
        if ip is None:
            continue
        try:
            addr = ipaddress.IPv4Address(str(ip))
        except ValueError:
            errors.append(f"{label} no es una IPv4 válida: {ip!r}")
            continue
        if net is not None and addr not in net:
            errors.append(f"{label} ({addr}) no pertenece a network.cidr ({net})")

    if not 15 <= sensor.sweep_interval <= 300:
        errors.append(f"sensor.sweep_interval fuera de rango 15..300: {sensor.sweep_interval}")
    if sensor.presence_misses < 1:
        errors.append("sensor.presence_misses debe ser >= 1")
    if sensor.heartbeat_interval < 5:
        errors.append("sensor.heartbeat_interval debe ser >= 5")
    if sensor.capture_idle_warn_s < 60:
        errors.append(
            f"sensor.capture_idle_warn_s debe ser >= 60: {sensor.capture_idle_warn_s}"
        )
    if sensor.retention_days < 1:
        errors.append("sensor.retention_days debe ser >= 1")
    if not 2 <= detect.window_s <= 600:
        errors.append(f"detect.window_s fuera de rango 2..600: {detect.window_s}")
    for name, val in (("syn_ports_warn", detect.syn_ports_warn),
                      ("syn_ports_crit", detect.syn_ports_crit),
                      ("syn_dsts_crit", detect.syn_dsts_crit),
                      ("arp_sweep_ips", detect.arp_sweep_ips)):
        if val < 1:
            errors.append(f"detect.{name} debe ser >= 1")
    if detect.syn_ports_warn >= detect.syn_ports_crit:
        errors.append("detect.syn_ports_warn debe ser menor que detect.syn_ports_crit")
    if detect.cooldown_s < 0:
        errors.append("detect.cooldown_s no puede ser negativo")
    if scan.quick_timeout < 1:
        errors.append(f"scan.quick_timeout debe ser >= 1: {scan.quick_timeout}")
    if scan.udp_timeout < 5:
        errors.append(f"scan.udp_timeout debe ser >= 5: {scan.udp_timeout}")
    if scan.quick_periodic_hours < 1:
        errors.append(f"scan.quick_periodic_hours debe ser >= 1: {scan.quick_periodic_hours}")
    if scan.weekly_rescan_days < 1:
        errors.append(f"scan.weekly_rescan_days debe ser >= 1: {scan.weekly_rescan_days}")
    if not 1 <= dashboard.port <= 65535:
        errors.append(f"dashboard.port inválido: {dashboard.port}")
    if not 1 <= dashboard.live_poll_s <= 60:
        errors.append(
            "dashboard.live_poll_s fuera de rango 1..60: "
            f"{dashboard.live_poll_s}"
        )
    if dashboard.host not in ("127.0.0.1", "localhost", "::1") and not dashboard.auth_token:
        errors.append(
            f"dashboard.host={dashboard.host!r} expone el panel fuera de loopback: "
            "definir DASHBOARD_TOKEN en .env (RNF-05)"
        )
    if not 0.5 <= notify.timeout_s <= 60:
        errors.append(f"notify.timeout_s fuera de rango 0.5..60: {notify.timeout_s}")
    valid_channels = {"local", "telegram", "discord"}
    for ch in notify.channels:
        if not isinstance(ch, dict) or ch.get("type") not in valid_channels:
            errors.append(f"notify.channels: canal inválido {ch!r}")

    if errors:
        raise ConfigError(errors)

    cfg = Config(root=base, network=network, sensor=sensor, scan=scan,
                 detect=detect, notify=notify, dashboard=dashboard, paths=paths,
                 interface_auto=interface_auto, cidr_auto=cidr_auto, warnings=warnings)
    cfg.ensure_dirs()
    return cfg


def load(config_path: str = "config.yaml", root: str | Path | None = None) -> Config:
    """Carga .env y después config.yaml."""
    base = Path(root or Path.cwd())
    load_dotenv(base / ".env")
    return load_config(config_path, base)
