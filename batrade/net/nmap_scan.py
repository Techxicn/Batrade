"""Perfilado con nmap: perfiles, ejecución sin shell y parseo XML endurecido.

RNF-05: sin ``shell=True``, argumentos en lista, objetivo validado contra el CIDR
y XML leído con defusedxml (nunca con el parser estándar).
"""
from __future__ import annotations

import logging
import os
import re
import stat
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from defusedxml import ElementTree as DET

from batrade.config import Config
from batrade.net.caps import Capabilities
from batrade.net.iputil import ip_in_cidr, now_ms, valid_ipv4

log = logging.getLogger("batrade.nmap")

PROFILES: dict[str, list[str]] = {
    # RF-07 rápido: -F son 100 puertos, no 1000 (corrección #2 del PRD).
    "quick": ["-F", "--version-light"],
    # RF-07 estándar: top 1000 + detección de versión ligera.
    "standard": ["-sV", "--top-ports", "1000", "--version-light"],
    # RF-09 bajo demanda, intrusivo.
    "vuln": ["-sV", "--script", "vuln"],
}

PROFILE_TIMEOUT = {"quick": 120, "standard": 300, "vuln": 900}
HOST_TIMEOUT = {"quick": "60s", "standard": "120s", "vuln": "300s"}

# Pasada UDP de los puertos del catálogo: acotada a propósito, porque UDP no
# responde y nmap debe esperar timeouts. Sólo se ejecuta con CAP_NET_RAW.
# La detección de versión (-sV) es lo que convierte un `open|filtered` en
# `open` cuando el servicio contesta a la sonda; sin ella SSDP/mDNS se quedan
# casi siempre en `open|filtered` y no se puede afirmar nada.
UDP_MAX_RETRIES = "1"
UDP_PROCESS_MARGIN_S = 30


def udp_timeouts(cfg: Config) -> tuple[int, int]:
    """(host-timeout, timeout de proceso) de la pasada UDP, en segundos.

    El proceso debe durar más que el host-timeout para que nmap alcance a
    escribir el XML, pero no mucho más: 30 s de margen.
    """
    host = max(1, int(cfg.scan.udp_timeout))
    return host, host + UDP_PROCESS_MARGIN_S


def profile_timeout(cfg: Config, profile: str) -> int:
    """Límite de proceso del perfil, respetando ``scan.*_timeout`` del YAML.

    ``quick_timeout`` sustituye al valor fijo de 120 s del perfil rápido; el
    perfil ``standard`` mantiene su tope histórico y ``vuln`` es siempre el más
    largo porque ejecuta scripts.
    """
    default = PROFILE_TIMEOUT.get(profile, 300)
    if profile == "quick":
        return max(1, int(cfg.scan.quick_timeout))
    if profile == "standard":
        return max(1, min(default, int(cfg.scan.standard_timeout)))
    return default


class ScanError(RuntimeError):
    pass


# Lo que ve el operador cuando el objetivo no da resultado. No es un fallo de la
# herramienta: nmap funciona, es el equipo el que no responde o filtra paquetes.
TARGET_UNREACHABLE = (
    "El escaneo de {ip} no terminó (el equipo no responde o filtra paquetes). "
    "Se reintentará más tarde; puedes excluirlo en scan.exclude"
)


class TargetScanError(ScanError):
    """El objetivo no dio un resultado utilizable: timeout o XML incompleto.

    Es un fallo **del objetivo**, no de la herramienta: no debe incrementar
    ``tool_status.fallos_consecutivos`` (eso es para un nmap roto) y sí dejar la
    fila de ``scans`` en ``error``, que es lo que frena el reintento inmediato.
    """

    def __init__(self, ip: str, motivo: str, detalle: str = "") -> None:
        self.ip = ip
        self.motivo = motivo  # "timeout" | "XML incompleto"
        self.detalle = detalle
        # Texto exacto para el operador, tal cual va a `scans.error` y a /health.
        self.mensaje = TARGET_UNREACHABLE.format(ip=ip)
        super().__init__(f"{motivo}: {detalle}" if detalle else motivo)


@dataclass(slots=True)
class ScanResult:
    target: str
    profile: str
    ports: list[dict[str, Any]] = field(default_factory=list)
    hostnames: list[str] = field(default_factory=list)
    xml_path: str | None = None
    cmd: list[str] = field(default_factory=list)
    exit_code: int | None = None
    duration_ms: int = 0
    notes: list[str] = field(default_factory=list)
    # Protocolos realmente explorados: si UDP no se pudo escanear, sus puertos
    # conocidos no deben marcarse como cerrados.
    protocols: set[str] = field(default_factory=lambda: {"tcp"})


def build_argv(cfg: Config, target: str, profile: str, caps: Capabilities,
               xml_path: Path) -> list[str]:
    if profile not in PROFILES:
        raise ScanError(f"perfil desconocido: {profile}")
    if not ip_in_cidr(target, cfg.network.cidr):
        raise ScanError(f"objetivo fuera del CIDR configurado: {target}")
    style = "-sS" if caps.raw_capture else "-sT"
    argv = ["nmap", style, "-Pn", *PROFILES[profile],
            cfg.scan.timing, "--host-timeout", HOST_TIMEOUT[profile],
            "-oX", str(xml_path), target]
    return argv


def build_udp_argv(cfg: Config, target: str, caps: Capabilities,
                   xml_path: Path) -> list[str]:
    """argv de la pasada UDP acotada a los puertos UDP del catálogo.

    Devuelve ``[]`` cuando no hay nada que explorar: sin ``CAP_NET_RAW`` no se
    puede hacer un escaneo UDP real y nmap sólo devolvería ``open|filtered``.

    ``-sV --version-light`` es deliberado: la sonda de servicio es lo que
    permite que un SSDP o mDNS que responde pase de ``open|filtered`` a
    ``open``. Sin ella la pasada no produciría apenas hallazgos reales.
    """
    if not caps.raw_capture:
        return []
    udp_ports, _note = udp_risky_ports(cfg, caps)
    if not udp_ports:
        return []
    if not ip_in_cidr(target, cfg.network.cidr):
        raise ScanError(f"objetivo fuera del CIDR configurado: {target}")
    host_timeout, _proceso = udp_timeouts(cfg)
    return ["nmap", "-sU", "-sV", "--version-light", "-Pn",
            "-p", "U:" + ",".join(str(p) for p in udp_ports),
            cfg.scan.timing, "--host-timeout", f"{host_timeout}s",
            "--max-retries", UDP_MAX_RETRIES, "-oX", str(xml_path), target]


def run_scan(cfg: Config, target: str, profile: str = "standard",
             caps: Capabilities | None = None,
             timeout: int | None = None) -> ScanResult:
    """Ejecuta nmap y devuelve puertos y hostnames. No lanza por fallo de red."""
    target = valid_ipv4(target) or ""
    if not target:
        raise ScanError("objetivo IPv4 inválido")
    caps = caps or Capabilities()
    cfg.paths.scans_dir.mkdir(parents=True, exist_ok=True)
    try:
        cfg.paths.scans_dir.chmod(0o700)
    except OSError:
        pass

    xml_path = cfg.paths.scans_dir / f"scan-{profile}-{target}-{int(time.time())}.xml"
    argv = build_argv(cfg, target, profile, caps, xml_path)
    limit = timeout or profile_timeout(cfg, profile)
    start = now_ms()
    result = ScanResult(target=target, profile=profile, xml_path=str(xml_path), cmd=argv)

    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=limit,
                              check=False)
        result.exit_code = proc.returncode
        stderr = proc.stderr.strip()
    except subprocess.TimeoutExpired:
        # Un nmap muerto por timeout deja el XML a medias: ni se intenta parsear.
        _safe_unlink(xml_path)
        raise TargetScanError(target, "timeout",
                              f"nmap excedió {limit}s") from None
    except OSError as exc:
        raise ScanError(f"no se pudo ejecutar nmap: {exc}") from exc

    result.duration_ms = now_ms() - start
    if not xml_path.exists():
        raise ScanError(f"nmap no generó XML (código {result.exit_code}): {stderr[:200]}")
    try:
        parsed = parse_xml(xml_path)
    except Exception as exc:
        # Cabecera sin cierre o archivo vacío: el intento fallido no se queda en
        # disco esperando a la retención de 90 días.
        _safe_unlink(xml_path)
        raise TargetScanError(target, "XML incompleto", str(exc)[:200]) from exc
    result.ports = parsed["ports"]
    result.hostnames = parsed["hostnames"]
    try:
        xml_path.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 600
    except OSError:
        pass
    if result.exit_code not in (0, None):
        result.notes.append(f"nmap terminó con código {result.exit_code}")
    _run_udp_pass(cfg, target, caps, result)
    return result


def _run_udp_pass(cfg: Config, target: str, caps: Capabilities,
                  result: ScanResult) -> None:
    """Pasada UDP opcional (UPnP/SSDP, mDNS) cuando hay CAP_NET_RAW.

    Un fallo de esta pasada no invalida el escaneo TCP: se anota y se sigue.
    Sólo se conservan los puertos en estado ``open``; ``open|filtered`` es lo
    habitual en UDP y no demuestra que el servicio exista.
    """
    udp_path = cfg.paths.scans_dir / f"scan-udp-{target}-{int(time.time() * 1000)}.xml"
    try:
        argv = build_udp_argv(cfg, target, caps, udp_path)
    except ScanError as exc:
        result.notes.append(str(exc))
        return
    if not argv:
        return
    _host_timeout, udp_proceso = udp_timeouts(cfg)
    try:
        proc = subprocess.run(argv, capture_output=True, text=True,
                              timeout=udp_proceso, check=False)
    except subprocess.TimeoutExpired:
        _safe_unlink(udp_path)
        result.notes.append(f"la pasada UDP excedió {udp_proceso}s")
        return
    except OSError as exc:
        _safe_unlink(udp_path)
        result.notes.append(f"no se pudo ejecutar la pasada UDP: {exc}")
        return
    try:
        if not udp_path.exists():
            result.notes.append(f"la pasada UDP no generó XML (código {proc.returncode})")
            return
        parsed = parse_xml(udp_path)
        for port in parsed["ports"]:
            port["protocol"] = "udp"
            result.ports.append(port)
        result.protocols.add("udp")
        if proc.returncode not in (0, None):
            result.notes.append(f"la pasada UDP terminó con código {proc.returncode}")
    except Exception as exc:  # noqa: BLE001 - nunca invalidar el resultado TCP
        result.notes.append(f"XML de la pasada UDP inválido: {exc}")
    finally:
        # La fila de `scans` referencia un único XML: los puertos UDP ya están
        # volcados y el archivo no debe quedar fuera de la retención.
        _safe_unlink(udp_path)


def parse_xml(path: str | Path) -> dict[str, Any]:
    """Parsea el XML de nmap con defusedxml (bloquea entidades externas)."""
    raw = Path(path).read_bytes()
    # Se elimina la declaración DOCTYPE completa (nmap la incluye); hacerlo por
    # reemplazo textual simple dejaría un fragmento inválido.
    raw = re.sub(rb"<!DOCTYPE[^>]*>", b"", raw, flags=re.IGNORECASE)
    root = DET.fromstring(raw)
    ports: list[dict[str, Any]] = []
    hostnames: list[str] = []

    for hostname in root.iter("hostname"):
        name = (hostname.get("name") or "").strip()
        if name:
            hostnames.append(name)

    for port in root.iter("port"):
        state_el = port.find("state")
        state = (state_el.get("state") if state_el is not None else "") or ""
        if state != "open":
            continue
        service_el = port.find("service")
        service = version = None
        if service_el is not None:
            service = service_el.get("name")
            product = service_el.get("product") or ""
            ver = service_el.get("version") or ""
            extra = service_el.get("extrainfo") or ""
            version = " ".join(p for p in (product, ver, extra) if p).strip() or None
        try:
            portid = int(port.get("portid", "0"))
        except (TypeError, ValueError):
            continue
        ports.append({
            "port": portid,
            "protocol": (port.get("protocol") or "tcp").lower(),
            "state": state,
            "service": service,
            "version": version,
        })
    return {"ports": ports, "hostnames": hostnames}


def _safe_unlink(path: Path) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass


def udp_risky_ports(cfg: Config, caps: Capabilities) -> tuple[list[int], str | None]:
    """Puertos UDP del catálogo y la nota que explica por qué no se exploran.

    Sin ``CAP_NET_RAW`` no se puede hacer un escaneo UDP real: nmap marcaría
    todo como ``open|filtered`` y generaríamos falsos positivos. La nota se
    registra una vez por ejecución y se muestra en ``/health``.
    """
    udp = sorted(p.port for p in cfg.scan.risky_ports.values() if p.protocol == "udp")
    if not udp:
        return [], None
    if not caps.raw_capture:
        return [], ("UDP no verificable sin CAP_NET_RAW: los puertos "
                    f"{udp} (UPnP/SSDP, mDNS) no se evalúan en modo degradado")
    return udp, None
