"""Descubrimiento de la subred: arp-scan si hay privilegios, si no tabla de vecinos.

RF-01 exige un barrido cada 30 s y un plan B ante el fallo de arp-scan. El plan B
del PRD (``nmap -sn -PR``) también necesita CAP_NET_RAW, así que aquí se usa una
cadena que degrada de verdad: arp-scan -> sondeo TCP + ``ip neigh``.
"""
from __future__ import annotations

import logging
import re
import subprocess
from dataclasses import dataclass

from batrade.config import Config
from batrade.net import caps as caps_mod
from batrade.net.neigh import probe_cidr, read_neighbors
from batrade.net.iputil import ip_in_cidr, normalize_mac, valid_ipv4
from batrade.net.proc import env_minimo

log = logging.getLogger("batrade.discovery")

ARP_LINE = re.compile(r"^(?P<ip>\d+\.\d+\.\d+\.\d+)\s+(?P<mac>[0-9a-fA-F:]{17})\s*(?P<vendor>.*)$")


class DiscoveryError(RuntimeError):
    """El barrido no pudo completarse; el ciclo principal debe seguir vivo."""


@dataclass(slots=True)
class SweepResult:
    hosts: dict[str, str]        # ip -> mac
    backend: str                 # arp-scan | neigh
    degraded: bool
    duration_ms: int


class Discovery:
    def __init__(self, cfg: Config, capabilities: caps_mod.Capabilities | None = None):
        self.cfg = cfg
        self.caps = capabilities or caps_mod.probe()

    @property
    def backend(self) -> str:
        if self.caps.raw_capture and self.caps.arp_scan:
            return "arp-scan"
        return "neigh"

    def sweep(self) -> SweepResult:
        """Barrido completo. Lanza DiscoveryError sólo si todas las vías fallan."""
        import time

        start = int(time.time() * 1000)
        errors: list[str] = []

        if self.caps.raw_capture and self.caps.arp_scan:
            try:
                hosts = self._arp_scan()
                return SweepResult(hosts, "arp-scan", False,
                                   int(time.time() * 1000) - start)
            except DiscoveryError as exc:
                errors.append(f"arp-scan: {exc}")
                log.warning("arp-scan falló, se degrada a tabla de vecinos")

        try:
            hosts = self._neigh_sweep()
            return SweepResult(hosts, "neigh", True, int(time.time() * 1000) - start)
        except DiscoveryError as exc:
            errors.append(f"neigh: {exc}")

        raise DiscoveryError("; ".join(errors) or "sin vía de descubrimiento")

    # -------------------------------------------------------------- interno
    def _arp_scan(self) -> dict[str, str]:
        argv = [
            "arp-scan",
            "--interface", self.cfg.network.interface,
            "--plain", "--ignoredups", "--retry", "2",
            self.cfg.network.cidr,
        ]
        try:
            proc = subprocess.run(argv, capture_output=True, text=True,
                                  timeout=max(15, self.cfg.sensor.sweep_interval),
                                  env=env_minimo())
        except subprocess.TimeoutExpired as exc:
            raise DiscoveryError(f"timeout tras {exc.timeout}s") from exc
        except OSError as exc:
            raise DiscoveryError(str(exc)) from exc
        if proc.returncode not in (0,):
            # arp-scan devuelve 1 cuando no encuentra nada; sólo es error real si no hay salida
            if not proc.stdout.strip():
                raise DiscoveryError(
                    f"código {proc.returncode}: {proc.stderr.strip()[:200]}")
        return self._parse_plain(proc.stdout)

    @staticmethod
    def _parse_plain(text: str) -> dict[str, str]:
        hosts: dict[str, str] = {}
        for line in text.splitlines():
            m = ARP_LINE.match(line.strip())
            if not m:
                continue
            ip = valid_ipv4(m.group("ip"))
            mac = normalize_mac(m.group("mac"))
            if ip and mac:
                hosts[ip] = mac
        return hosts

    def _neigh_sweep(self) -> dict[str, str]:
        """Sondeo sin privilegios: connect TCP para forzar ARP + lectura de vecinos."""
        try:
            probe_cidr(self.cfg.network.cidr, timeout=0.35)
        except OSError as exc:
            raise DiscoveryError(str(exc)) from exc
        table = read_neighbors(self.cfg.network.interface)
        self_ip = self._own_ip()
        hosts: dict[str, str] = {}
        for ip, mac in table.items():
            if ip == self_ip:
                continue
            if ip_in_cidr(ip, self.cfg.network.cidr):
                hosts[ip] = mac
        return hosts

    def _own_ip(self) -> str | None:
        from batrade.net.iputil import interface_ipv4
        return interface_ipv4(self.cfg.network.interface)
