"""Gestión de activos: presencia, identidad y modo aprendizaje (RF-01..06).

Convierte transiciones de inventario en hallazgos con severidad según la matriz
de la sección 10 del PRD.
"""
from __future__ import annotations

import sqlite3
from typing import Any

from batrade import store
from batrade.config import Config
from batrade.detect.observation import Finding
from batrade.net.iputil import (ip_in_cidr, is_locally_administered,
                                normalize_mac, now_ms, valid_ipv4)
from batrade.net.oui import OuiDB


def _finding(tipo: str, severidad: str, clave: str, *, resumen: str, por_que: str,
             accion: str, ip: str | None = None, mac: str | None = None,
             notificar: bool = True, **extra) -> Finding:
    return Finding(tipo=tipo, severidad=severidad, clave=clave, ip_origen=ip,
                   mac_origen=mac, detalle={"resumen": resumen, "por_que": por_que,
                                            "accion": accion, **extra},
                   notificar=notificar)


class Inventory:
    def __init__(self, conn: sqlite3.Connection, cfg: Config, oui: OuiDB,
                 learning: bool = True):
        self.conn = conn
        self.cfg = cfg
        self.oui = oui
        self.learning = learning

    # ------------------------------------------------------------------ API
    def observe_host(self, ip: str | None, mac: str, ts: int | None = None, *,
                     hostname: str | None = None,
                     source: str = "sweep") -> list[Finding]:
        """Registra un avistamiento y devuelve los hallazgos de inventario."""
        ts = ts or now_ms()
        mac_n = normalize_mac(mac)
        if not mac_n:
            return []
        ip_n = valid_ipv4(ip)
        random_mac = is_locally_administered(mac_n)
        # Una MAC local no tiene OUI significativo: el fabricante sería basura.
        vendor = None if random_mac else self.oui.lookup(mac_n)

        state = store.upsert_device(
            self.conn, mac=mac_n, ip=ip_n, ts=ts, hostname=_clean_hostname(hostname),
            fabricante=vendor, mac_aleatoria=random_mac,
        )
        device_id = int(state["device_id"])
        findings: list[Finding] = []

        if state["created"]:
            findings.append(self._new_device_finding(
                device_id, mac_n, ip_n, vendor, random_mac,
                same_identity=not state["identity_created"], ts=ts, source=source
            ))
        elif state["came_online"]:
            findings.append(self._reconnect_finding(
                device_id, mac_n, ip_n, str(state["estado_confianza"]), ts
            ))
        return findings

    def apply_sweep(self, seen: dict[str, str], ts: int | None = None) -> list[Finding]:
        """Aplica un barrido completo: altas, reconexiones y ausencias (RF-05)."""
        ts = ts or now_ms()
        findings: list[Finding] = []
        seen_macs: set[str] = set()

        for ip, mac in seen.items():
            mac_n = normalize_mac(mac)
            if not mac_n:
                continue
            seen_macs.add(mac_n)
            findings.extend(self.observe_host(ip, mac_n, ts, source="sweep"))

        # Ausencias: sólo equipos en línea pertenecientes a la subred vigilada
        # (L-04: evita desconexiones espurias si la base conserva equipos de otra red).
        for device_id in store.online_device_ids(self.conn):
            device = store.get_device(self.conn, device_id)
            if device is None or device["mac"] in seen_macs:
                continue
            ip_actual = device["ip_actual"]
            if ip_actual and not ip_in_cidr(ip_actual, self.cfg.network.cidr):
                continue
            transition = store.register_miss(
                self.conn, int(device["id"]), ts, self.cfg.sensor.presence_misses
            )
            if transition:
                findings.append(_finding(
                    "device_offline", "info", f"device:offline:{device['mac']}",
                    resumen=f"{self._label(device)} dejó de responder",
                    por_que="El equipo se desconectó o perdió cobertura.",
                    accion="Ninguna si es esperado.",
                    ip=device["ip_actual"], mac=device["mac"], notificar=False,
                ))
        return findings

    def label(self, device: sqlite3.Row | dict[str, Any]) -> str:
        return self._label(device)

    # -------------------------------------------------------------- interno
    def _label(self, device: Any) -> str:
        alias = device["alias"] if "alias" in device.keys() else None
        host = device["hostname"] if "hostname" in device.keys() else None
        ip = device["ip_actual"] if "ip_actual" in device.keys() else None
        return alias or host or ip or device["mac"]

    def _new_device_finding(self, device_id: int, mac: str, ip: str | None,
                            vendor: str | None, random_mac: bool, *,
                            same_identity: bool, ts: int, source: str) -> Finding:
        nombre = vendor or "fabricante desconocido"
        if same_identity:
            return _finding(
                "device_mac_rotated", "info", f"device:new:{mac}",
                resumen=f"Nueva MAC ({mac}) del mismo equipo ya conocido",
                por_que="El dispositivo cambió de MAC (MAC aleatoria por red o periodo).",
                accion="Ninguna: ya está agrupado con su equipo por hostname.",
                ip=ip, mac=mac, notificar=False, vendor=vendor, identity_reused=True,
            )
        severity = "info" if self.learning else "warn"
        return _finding(
            "device_new", severity, f"device:new:{mac}",
            resumen=f"Dispositivo nuevo en la red: {ip or 'IP desconocida'} ({nombre})",
            por_que=("Es la primera vez que se ve este equipo en la subred vigilada. "
                     "Podría ser un invitado, un IoT recién instalado o un intruso."),
            accion=("Confirmar qué equipo es desde el panel y clasificarlo como "
                    "Confiable o No autorizado."),
            ip=ip, mac=mac, notificar=not self.learning, vendor=vendor,
            random_mac=random_mac, source=source, device_id=device_id,
        )

    def _reconnect_finding(self, device_id: int, mac: str, ip: str | None,
                           estado: str, ts: int) -> Finding:
        device = store.get_device(self.conn, device_id)
        nombre = self._label(device) if device else mac
        if estado == "no_autorizado":
            return _finding(
                "device_unauthorized_online", "crit",
                f"device:unauth:{device_id}",
                resumen=f"El dispositivo NO AUTORIZADO {nombre} ({ip}) volvió a conectarse",
                por_que=("Un equipo que ya habías marcado como no autorizado está en la "
                         "red otra vez."),
                accion="Identificarlo físicamente y desconectarlo del router.",
                ip=ip, mac=mac, device_id=device_id,
            )
        return _finding(
            "device_online", "info", f"device:online:{device_id}",
            resumen=f"{nombre} ({ip}) volvió a estar en línea",
            por_que="Reconexión normal de un equipo conocido.",
            accion="Ninguna.",
            ip=ip, mac=mac, notificar=False, device_id=device_id, estado=estado,
        )


def _clean_hostname(hostname: str | None) -> str | None:
    """El hostname viene de la red y se trata como no confiable (RNF-05)."""
    if not hostname:
        return None
    clean = "".join(ch for ch in str(hostname).strip()[:63] if ch.isprintable())
    clean = clean.strip()
    if not clean or clean.lower() in ("localhost", "unknown", "-"):
        return None
    return clean


# --------------------------------------------------------------------------- #
# Línea base (RF-04 / C7)
# --------------------------------------------------------------------------- #
def status(conn: sqlite3.Connection) -> dict[str, Any]:
    learning = (store.get_meta(conn, "learning_complete", "0") or "0") != "1"
    return {
        "learning": learning,
        "approved_at": store.get_meta(conn, "baseline_approved_ts"),
        "gateway_ip": store.get_meta(conn, "gateway_ip"),
        "gateway_mac": store.get_meta(conn, "gateway_mac"),
        "dhcp_server_ip": store.get_meta(conn, "dhcp_server_ip"),
        "devices": store.count_devices(conn),
        "pending_review": len(review_candidates(conn)),
    }


def review_candidates(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    """Equipos que no deberían aprobarse en lote (C7)."""
    return store.review_candidate_devices(conn)


def approve_baseline(conn: sqlite3.Connection, ts: int | None = None,
                     include_random_mac: bool = False) -> dict[str, int]:
    """Aprueba el inventario como línea base.

    Por defecto las MAC localmente administradas quedan en 'desconocido' para
    revisión individual: aprobarlas en lote legitima a cualquiera que ya estuviera
    conectado al arrancar.
    """
    ts = ts or now_ms()
    confirmed, remaining = store.approve_unknown_devices(
        conn, include_random_mac=include_random_mac
    )
    store.set_meta(conn, "learning_complete", "1", ts)
    store.set_meta(conn, "baseline_approved_ts", str(ts), ts)
    return {"aprobados": confirmed, "pendientes": remaining}


def begin_learning(conn: sqlite3.Connection, ts: int | None = None) -> None:
    store.set_meta(conn, "learning_complete", "0", ts or now_ms())
