"""Sniffer pasivo con scapy (sólo modo live).

Requiere CAP_NET_RAW. En esta VM no está disponible, por eso el proyecto separa
la conversión paquete->observación en ``scenarios.observation_from_packet``, que
se prueba con pcaps sin necesidad de privilegios.
"""
from __future__ import annotations

import logging
import threading
import time
from typing import Callable

from batrade.detect.observation import Observation
from batrade.detect.scenarios import observation_from_packet

log = logging.getLogger("batrade.sniffer")

# ARP + DHCP + SYN. Un BPF demasiado amplio tiraría la CPU del hogar.
DEFAULT_FILTER = "arp or udp port 67 or udp port 68 or (tcp and tcp[tcpflags] & tcp-syn != 0)"
# Con el motor de flujos activo hacen falta conversaciones completas (ARP e
# IPv4 TCP/UDP), no sólo SYN y DHCP; las reglas siguen recibiendo lo suyo
# porque `observation_from_packet` descarta TCP sin SYN y UDP distinto de DHCP.
FLOW_FILTER = "arp or (ip and (tcp or udp))"


def sniff_observations(iface: str, on_observation: Callable[[Observation], None],
                       stop_event: threading.Event,
                       bpf: str | None = None,
                       sensor_mac: str | None = None,
                       on_packet: Callable[[object, int], object] | None = None) -> None:
    """Bucle de captura que respeta ``stop_event`` y no acumula paquetes.

    ``sensor_mac`` sólo etiqueta la dirección de las observaciones (in/out); sin
    él quedan en ``None``, que es lo correcto para un puerto espejo.

    ``on_packet(pkt, ts)`` recibe cada paquete crudo **antes** de convertirlo
    (lo usa el motor de flujos). Sin ``bpf`` explícito, con ``on_packet`` se
    usa ``FLOW_FILTER`` para que el motor vea las conversaciones completas; sin
    ``on_packet`` se mantiene ``DEFAULT_FILTER``.
    """
    try:
        from scapy.all import sniff
    except Exception as exc:  # noqa: BLE001
        log.error("scapy no disponible: %s", exc)
        return

    filtro = (bpf if bpf is not None
              else (FLOW_FILTER if on_packet is not None else DEFAULT_FILTER))
    packets = 0

    def handle(pkt) -> None:
        nonlocal packets
        packets += 1
        ts = int(time.time() * 1000)
        if on_packet is not None:
            # Un fallo del consumidor de flujos no puede tumbar la captura.
            try:
                on_packet(pkt, ts)
            except Exception:  # noqa: BLE001
                log.exception("fallo entregando el paquete al motor de flujos")
        try:
            obs = observation_from_packet(pkt, ts, iface=iface, sensor_mac=sensor_mac)
        except Exception:  # noqa: BLE001
            log.exception("no se pudo convertir un paquete")
            return
        if obs is not None:
            try:
                on_observation(obs)
            except Exception:  # noqa: BLE001
                log.exception("fallo procesando la observación")

    while not stop_event.is_set():
        try:
            # store=False es obligatorio: acumular paquetes rompe el KPI de memoria.
            # promisc=True es obligatorio en un puerto espejo (SPAN): el tráfico
            # replicado conserva su MAC destino original (la del gateway, la del
            # host que habla, difusión...), y sin modo promiscuo la tarjeta
            # descarta en hardware toda trama cuya MAC destino no sea la suya.
            # El filtro BPF se aplica después, así que no se procesa de más.
            sniff(iface=iface, filter=filtro, prn=handle, store=False, timeout=2,
                  promisc=True)
        except PermissionError:
            log.error("sin CAP_NET_RAW: sniffer deshabilitado")
            return
        except OSError as exc:
            log.warning("error de captura (%s); reintentando en 5 s", exc)
            if stop_event.wait(5):
                return
        except Exception as exc:  # noqa: BLE001
            log.exception("sniffer detenido por error: %s", exc)
            return
    log.info("sniffer detenido tras %d paquetes", packets)
