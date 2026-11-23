"""Daemon batrade-sensor: orquesta descubrimiento, detección y notificación.

Un solo proceso, varios hilos, cada uno con su propia conexión SQLite (WAL
permite lectores concurrentes; el escritor está serializado por busy_timeout).

Modos:
  live      arp-scan + sniffing pasivo con scapy (requiere CAP_NET_RAW)
  degraded  sondeo TCP + tabla de vecinos + netlink (esta VM)
  replay    alimenta el motor desde un .pcap grabado
  simulate  alimenta el motor con tráfico sintético (demo y tests)
"""
from __future__ import annotations

import json
import logging
import queue
import signal
import threading
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Iterable

from batrade import db, store
from batrade.config import Config
from batrade.detect import scenarios
from batrade.detect.engine import Engine
from batrade.detect.observation import ARP, NEIGH, Observation
from batrade.detect.state import Baseline
from batrade.inventory import Inventory, status as baseline_status
from batrade.net import caps as caps_mod
from batrade.net.discovery import Discovery, DiscoveryError
from batrade.net.iputil import (default_gateway, interface_ipv4, ip_excluded,
                                ip_in_cidr, normalize_mac, now_ms)
from batrade.net.neigh import NeighborWatcher
from batrade.net.nmap_scan import (ScanError, TargetScanError, run_scan,
                                   udp_risky_ports)
from batrade.net.oui import OuiDB
from batrade.net.verify import (ESTADO_CONFIRMADO, ESTADO_DESCARTADO,
                                ESTADO_NO_VERIFICABLE, estado_verificacion,
                                interpret, probe_binding)
from batrade.notify import Notifier

log = logging.getLogger("batrade.sensor")

# Hilos cuya muerte deja al sensor ciego o mudo: se registran como `crit` y se
# reintentan con espera creciente. El resto sólo se registra.
HILOS_CRITICOS = frozenset({"batrade-sniff", "batrade-sweep", "batrade-neigh",
                            "batrade-notify"})
# Reintentos por hilo y ventana móvil: más de esto en una hora es un bucle roto.
MAX_REINICIOS_HORA = 5
REINICIO_BASE_MS = 5_000
REINICIO_MAX_MS = 300_000
VENTANA_REINICIOS_MS = 3_600_000

# Sondas ARP simultáneas. Un ataque sostenido puede generar muchos eventos con
# `needs_verify`; el pool evita la rotación sin límite de hilos efímeros.
VERIFY_WORKERS = 4
VERIFY_QUEUE_MAX = 64


def safe_unlink_scan(scans_dir: str | Path, candidate: str | Path) -> bool:
    """Elimina un XML de escaneo sólo si está realmente dentro de ``scans_dir``.

    La ruta viene de la base de datos, así que se resuelve (siguiendo enlaces
    simbólicos) y se comprueba la contención: un valor manipulado como
    ``../../etc/passwd`` o un symlink que apunta fuera nunca se borra. Un
    archivo ya inexistente se tolera sin error.
    """
    try:
        base = Path(scans_dir).resolve()
        path = Path(candidate).resolve()
    except (OSError, RuntimeError):  # ruta imposible o bucle de symlinks
        log.warning("XML de escaneo con ruta no resoluble; se ignora")
        return False
    if path.suffix.lower() != ".xml" or path == base or not path.is_relative_to(base):
        log.warning("XML de escaneo fuera de %s; no se borra %s",
                    base.name, path.name)
        return False
    if not path.exists():
        return False
    try:
        path.unlink()
        return True
    except OSError as exc:
        log.warning("no se pudo borrar %s: %s", path.name, exc)
        return False


@dataclass(slots=True)
class ScanJob:
    ip: str
    profile: str
    device_id: int | None = None
    request_id: int | None = None


class Sensor:
    def __init__(self, cfg: Config, mode: str = "auto", *,
                 scenario: str | None = None, pcap: str | None = None,
                 speed: float = 5.0, duration: float | None = None):
        self.cfg = cfg
        self.caps = caps_mod.probe()
        self.mode, self.mode_notes = caps_mod.resolve_mode(mode, self.caps)
        self.scenario = scenario
        self.pcap = pcap
        self.speed = max(1.0, float(speed))
        self.duration = duration
        self.stop_event = threading.Event()
        self._closed = False
        self._local = threading.local()
        self._lock = threading.RLock()
        self._pending: set[tuple[str, str]] = set()
        self.scan_queue: queue.Queue[ScanJob | None] = queue.Queue(maxsize=64)
        self._verify_queue: queue.Queue[tuple[int, str] | None] = queue.Queue(
            maxsize=VERIFY_QUEUE_MAX)
        self._verify_started = False
        self._threads: list[threading.Thread] = []
        self._supervisados: dict[str, dict] = {}
        self._ultima_obs_ts: int | None = None
        self._contadores = {"arp": 0, "syn": 0, "dhcp": 0, "neigh": 0}
        self.started_ts = now_ms()
        self.oui = OuiDB.load(cfg.paths.oui_file)
        self.conn = db.initialize(cfg.paths.db)
        recovered = db.recover_interrupted(self.conn, now_ms())
        if any(recovered.values()):
            log.info("estado recuperado tras reinicio", extra={"fields": recovered})
        self.engine = Engine(cfg, self._load_baseline())
        self.discovery = Discovery(cfg, self.caps)
        self.notifier = Notifier(cfg, lambda: db.connect(cfg.paths.db),
                                 env=self._env())
        self._wire_sensor_identity()

    # ------------------------------------------------------------------ setup
    def _env(self) -> dict[str, str]:
        """Sólo las variables que necesita el notificador (S-03).

        Nada de heredar el entorno completo: si un día se añade un token nuevo,
        se declara en su canal y sólo ese nombre viaja al `Notifier`.
        """
        import os

        nombres: set[str] = set()
        for canal in self.cfg.notify.channels:
            if not isinstance(canal, dict):
                continue
            tipo = str(canal.get("type", ""))
            if tipo == "telegram":
                nombres.add(str(canal.get("token_env") or "TELEGRAM_TOKEN"))
                nombres.add(str(canal.get("chat_id_env") or "TELEGRAM_CHAT_ID"))
            elif tipo == "discord":
                nombres.add(str(canal.get("webhook_env") or "DISCORD_WEBHOOK"))
        return {nombre: os.environ[nombre] for nombre in sorted(nombres)
                if os.environ.get(nombre)}

    def _load_baseline(self) -> Baseline:
        b = Baseline()
        # Prioridad: lo aprendido y guardado > config.yaml > ruta por defecto.
        gw = (store.get_meta(self.conn, "gateway_ip")
              or self.cfg.network.gateway_ip
              or default_gateway())
        if gw and not ip_in_cidr(gw, self.cfg.network.cidr):
            log.warning("gateway %s fuera de %s; se ignora como línea base",
                        gw, self.cfg.network.cidr)
            gw = None
        b.gateway_ip = gw
        b.gateway_mac = store.get_meta(self.conn, "gateway_mac")
        b.dhcp_server_ip = (store.get_meta(self.conn, "dhcp_server_ip")
                            or self.cfg.network.dhcp_server_ip)
        b.exceptions = set(self.cfg.detect.arp_exceptions)
        b.learning = baseline_status(self.conn)["learning"]
        return b

    def _wire_sensor_identity(self) -> None:
        ip = interface_ipv4(self.cfg.network.interface)
        mac = self._interface_mac(self.cfg.network.interface)
        self.engine.register_sensor(ip, mac)
        self.sensor_ip = ip
        self.sensor_mac = mac

    @staticmethod
    def _interface_mac(iface: str) -> str | None:
        try:
            raw = Path(f"/sys/class/net/{iface}/address").read_text().strip()
        except OSError:
            return None
        return normalize_mac(raw)

    def _conn(self):
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = db.connect(self.cfg.paths.db)
            self._local.conn = conn
        return conn

    # ------------------------------------------------------------------- API
    def start(self) -> None:
        self._log_startup()
        store.heartbeat(self.conn, "sensor", now_ms(), json.dumps({
            "mode": self.mode, "state": "starting",
        }))
        self._spawn(self._main_loop, "batrade-main")
        self._spawn(self.notifier.run, "batrade-notify")
        if self.mode in ("live", "degraded"):
            self._spawn(self._sweep_loop, "batrade-sweep")
            if self.cfg.sensor.neighbor_watch and self.caps.netlink_neigh:
                self._spawn(self._neigh_loop, "batrade-neigh")
            if self.mode == "live":
                self._spawn(self._sniff_loop, "batrade-sniff")
            for i in range(self.cfg.scan.max_concurrent if self.cfg.scan.enabled else 0):
                self._spawn(self._scan_worker, f"batrade-scan-{i}")
        elif self.mode in ("replay", "simulate"):
            self._spawn(self._feed_loop, "batrade-feed")

    def run(self) -> None:
        self.start()
        try:
            while not self.stop_event.is_set():
                self.stop_event.wait(0.5)
        except KeyboardInterrupt:
            log.info("interrupción recibida")
        finally:
            self.stop()

    def stop(self) -> None:
        # Idempotente: el manejador de señal ya pudo marcar stop_event antes
        # de que run() llame a stop(); aun así hay que cerrar una sola vez.
        if self._closed:
            return
        self._closed = True
        self.stop_event.set()
        self.notifier.stop_event.set()
        try:
            self.scan_queue.put_nowait(None)
        except queue.Full:
            pass
        for t in list(self._threads):
            t.join(timeout=3.0)
        try:
            store.heartbeat(self.conn, "sensor", now_ms(), json.dumps({
                "mode": self.mode, "state": "stopped"}))
            self.conn.close()
        except Exception:  # noqa: BLE001
            pass
        log.info("sensor detenido")

    # -------------------------------------------------------------- hilos
    def _spawn(self, target, name: str) -> None:
        self._supervisados[name] = {
            "objetivo": target,
            "critico": name in HILOS_CRITICOS,
            "reinicios": [],
            "detenido": False,
            "hilo": None,
        }
        hilo = threading.Thread(target=self._guard(name), name=name, daemon=True)
        self._supervisados[name]["hilo"] = hilo
        self._threads.append(hilo)
        hilo.start()

    def _guard(self, nombre: str):
        """Envuelve un hilo: registra la muerte, cierra su conexión y lo reintenta."""

        def runner():
            try:
                self._supervisados[nombre]["objetivo"]()
            except Exception as exc:
                log.exception("hilo %s terminó por excepción", nombre)
                try:
                    self._on_thread_death(nombre, exc, now_ms())
                except Exception:  # noqa: BLE001 - el guardián nunca puede caerse
                    log.exception("no se pudo registrar la muerte del hilo %s", nombre)
            finally:
                self._close_thread_conn()

        return runner

    def _close_thread_conn(self) -> None:
        """Cierra la conexión SQLite propia del hilo (la del thread-local)."""
        conn = getattr(self._local, "conn", None)
        if conn is None:
            return
        try:
            conn.close()
        except Exception:  # noqa: BLE001
            pass
        self._local.conn = None

    def _on_thread_death(self, nombre: str, exc: BaseException, ts: int) -> int | None:
        """Registra el evento y programa el reintento. Devuelve la espera o None."""
        entrada = self._supervisados.get(nombre)
        if entrada is None:
            # Hilo no registrado por `_spawn`: el libro de reintentos se lleva
            # igualmente, sin objetivo que relanzar.
            entrada = {"objetivo": None, "critico": nombre in HILOS_CRITICOS,
                       "reinicios": [], "detenido": False, "hilo": None}
            self._supervisados[nombre] = entrada
        critico = bool(entrada["critico"])
        reinicios = [t for t in entrada["reinicios"] if ts - t < VENTANA_REINICIOS_MS]
        entrada["reinicios"] = reinicios

        detenido = critico and len(reinicios) >= MAX_REINICIOS_HORA
        entrada["detenido"] = detenido

        self._emit_thread_event(nombre, exc, ts, critico=critico,
                                detenido=detenido, reinicios=len(reinicios))
        if not critico or detenido:
            return None
        espera = min(REINICIO_BASE_MS * (2 ** len(reinicios)), REINICIO_MAX_MS)
        reinicios.append(ts)
        self._schedule_restart(nombre, espera)
        return espera

    def _emit_thread_event(self, nombre: str, exc: BaseException, ts: int, *,
                           critico: bool, detenido: bool, reinicios: int) -> None:
        from batrade.detect.observation import Finding

        if detenido:
            resumen = f"El hilo {nombre} quedó detenido tras {reinicios} reinicios"
            accion = "Reinicia el sensor: ese hilo ya no se recupera solo."
            clave = f"thread:stopped:{nombre}"
        else:
            resumen = f"El hilo {nombre} murió por {type(exc).__name__}"
            accion = ("Se reintenta solo con espera creciente." if critico
                      else "Revisa el log del sensor.")
            clave = f"thread:died:{nombre}"
        finding = Finding(
            tipo="thread_died", severidad="crit" if (critico or detenido) else "warn",
            clave=clave,
            detalle={
                "resumen": resumen,
                "por_que": "Sin ese hilo el sensor pierde parte de su vigilancia.",
                "accion": accion,
                # Sólo nombre y tipo de excepción: nunca el mensaje ni el contexto.
                "hilo": nombre, "excepcion": type(exc).__name__, "reinicios": reinicios,
            },
        )
        self._persist(self._conn(), [finding], ts)

    def _schedule_restart(self, nombre: str, espera_ms: int) -> None:
        temporizador = threading.Timer(espera_ms / 1000.0, self._restart_thread,
                                       args=(nombre,))
        temporizador.daemon = True
        temporizador.start()

    def _restart_thread(self, nombre: str) -> None:
        if self.stop_event.is_set():
            return
        entrada = self._supervisados.get(nombre)
        if entrada is None or entrada["detenido"] or not callable(entrada.get("objetivo")):
            return
        hilo = threading.Thread(target=self._guard(nombre), name=nombre, daemon=True)
        entrada["hilo"] = hilo
        self._threads.append(hilo)
        hilo.start()

    def _neigh_loop(self) -> None:
        """Arranca la vigilancia de vecinos; si muere, el guardián la reintenta."""
        NeighborWatcher(self._on_neighbor, self.cfg.network.interface,
                        stop_event=self.stop_event).run()

    def _thread_alive(self, nombre: str) -> bool:
        entrada = self._supervisados.get(nombre)
        if not entrada or entrada.get("detenido"):
            return False
        hilo = entrada.get("hilo")
        return bool(hilo is not None and hilo.is_alive())

    # ------------------------------------------------- observabilidad de captura
    def _note_observation(self, kind: str, ts: int) -> None:
        """Contabiliza una observación para el latido (contadores acotados)."""
        clave = str(kind).lower()
        if clave not in self._contadores:
            return
        self._contadores[clave] = min(self._contadores[clave] + 1, 2 ** 31 - 1)
        self._ultima_obs_ts = int(ts)

    def _capture_state(self, ts: int) -> dict:
        ultima = self._ultima_obs_ts
        if self.mode != "live":
            estado = "no_aplica"
        else:
            estado = "viva" if self._thread_alive("batrade-sniff") else "detenida"
        return {
            "estado": estado,
            "ultima_obs_ts": ultima,
            "idle_s": None if ultima is None else max(0, (ts - ultima) // 1000),
            "contadores": dict(self._contadores),
        }

    def _check_capture_idle(self, conn, ts: int) -> bool:
        """Avisa (info, sin notificar) si en modo live no entra nada de tráfico."""
        if self.mode != "live":
            return False
        limite = self.cfg.sensor.capture_idle_warn_s * 1000
        ultima = self._ultima_obs_ts
        if ultima is None or ts - ultima < limite:
            return False
        from batrade.detect.observation import Finding

        minutos = max(1, (ts - ultima) // 60_000)
        finding = Finding(
            tipo="capture_idle", severidad="info", notificar=False,
            clave="capture:idle",
            detalle={
                "resumen": f"Sin observaciones de captura desde hace {minutos} min",
                "por_que": ("El sniffer sigue vivo pero no ve tráfico: interfaz "
                            "equivocada, permisos o la red está en silencio."),
                "accion": "Revisa /health y que el proceso tenga CAP_NET_RAW.",
                "idle_s": (ts - ultima) // 1000,
            },
        )
        self._persist(conn, [finding], ts)
        return True

    def _main_loop(self) -> None:
        import sqlite3

        conn = self._conn()
        last_purge = 0
        last_prune = 0
        while not self.stop_event.wait(1.0):
            ts = now_ms()
            try:
                self.engine.set_learning(baseline_status(conn)["learning"])
                # Solicitudes del dashboard
                for req in store.claim_scan_requests(conn):
                    self._enqueue_scan(ScanJob(ip=req["objetivo"], profile=req["perfil"],
                                               request_id=int(req["id"])), origin="dashboard")
                if ts - last_prune > 30_000:
                    self.engine.prune(ts)
                    last_prune = ts
                if ts - last_purge > 3600_000:
                    purged = self._purge_retention(conn, ts)
                    last_purge = ts
                    if any(purged.values()):
                        log.info("purga de retención", extra={"fields": purged})
                if ts - self._last_heartbeat() >= self.cfg.sensor.heartbeat_interval * 1000:
                    self._heartbeat(conn, ts)
                    self._check_capture_idle(conn, ts)
                if self.duration and (ts - self.started_ts) > self.duration * 1000:
                    log.info("duración alcanzada; deteniendo")
                    self.stop_event.set()
            except sqlite3.OperationalError as exc:
                log.warning("SQLite ocupado en el bucle principal: %s", exc)
            except Exception:
                log.exception("error en el bucle principal")

    def _last_heartbeat(self) -> int:
        return getattr(self, "_hb_ts", 0)

    def _purge_retention(self, conn, ts: int) -> dict:
        """Purga por antigüedad y borra los XML de los escaneos eliminados."""
        cutoff = ts - self.cfg.sensor.retention_days * 86400_000
        purged = store.purge(conn, cutoff)
        rutas = purged.pop("scan_xml", [])
        purged["xml"] = sum(
            1 for ruta in rutas if safe_unlink_scan(self.cfg.paths.scans_dir, ruta)
        )
        return purged

    def _heartbeat(self, conn, ts: int) -> None:
        self._hb_ts = ts
        detalle = {
            "mode": self.mode,
            "state": "running",
            "caps": self.caps.summary(),
            "engine": self.engine.snapshot(),
            "queue": self.scan_queue.qsize(),
            "notified": self.notifier.sent,
            "notify_failed": self.notifier.failed,
            "captura": self._capture_state(ts),
        }
        store.heartbeat(conn, "sensor", ts, json.dumps(detalle, default=str))

    # ------------------------------------------------- descubrimiento activo
    def _sweep_loop(self) -> None:
        conn = self._conn()
        inv = Inventory(conn, self.cfg, self.oui, learning=baseline_status(conn)["learning"])
        first = True
        while not self.stop_event.is_set():
            ts = now_ms()
            try:
                result = self.discovery.sweep()
                store.record_tool_status(conn, f"sweep:{result.backend}", ts, True)
                failures = 0
            except DiscoveryError as exc:
                failures = store.record_tool_status(conn, "sweep", ts, False, error=str(exc))
                log.warning("barrido falló (%s/%s): %s", failures,
                            self.cfg.sensor.presence_misses, exc)
                for f in self._tool_failure_findings("barrido de subred", str(exc), failures, ts):
                    self._persist(conn, [f], ts)
                self.stop_event.wait(self.cfg.sensor.sweep_interval)
                continue

            inv.learning = baseline_status(conn)["learning"]
            findings = inv.apply_sweep(result.hosts, ts)
            self._persist(conn, findings, ts)
            self._learn_gateway(conn, result.hosts, ts)
            self._schedule_scans(conn, result.hosts, ts)
            if first:
                first = False
                log.info("primer barrido", extra={"fields": {
                    "backend": result.backend, "hosts": len(result.hosts),
                    "ms": result.duration_ms, "degraded": result.degraded}})
            else:
                log.debug("barrido", extra={"fields": {
                    "backend": result.backend, "hosts": len(result.hosts)}})
            self.stop_event.wait(self.cfg.sensor.sweep_interval)

    def _learn_gateway(self, conn, hosts: dict[str, str], ts: int) -> None:
        gw = self.engine.baseline.gateway_ip
        if not gw or not self.engine.baseline.gateway_mac:
            if gw and hosts.get(gw):
                with self._lock:
                    self.engine.baseline.gateway_mac = hosts[gw]
                store.set_meta(conn, "gateway_ip", gw, ts)
                store.set_meta(conn, "gateway_mac", hosts[gw], ts)
                log.info("línea base: gateway %s = %s", gw, hosts[gw])
        else:
            store.set_meta(conn, "gateway_ip", gw, ts)

    def _schedule_scans(self, conn, hosts: dict[str, str], ts: int) -> None:
        """Programa los escaneos automáticos (RF-07, RF-10).

        - Primer avistamiento de un equipo -> perfil ``standard``.
        - Equipo ``confiable`` cuyo último ``standard`` correcto supera
          ``scan.weekly_rescan_days`` -> ``standard`` otra vez, pero
          escalonado: como mucho ``scan.max_concurrent`` por barrido y del más
          atrasado al más reciente, para no lanzar una ráfaga tras un periodo
          apagado.
        - Cualquier equipo cuyo último escaneo supera
          ``scan.quick_periodic_hours`` -> ``quick``.

        El coalescing lo hacen ``_pending`` (misma IP+perfil en vuelo) y el
        índice único parcial de ``scan_requests``.
        """
        if not self.cfg.scan.enabled:
            return
        quick_ms = int(self.cfg.scan.quick_periodic_hours) * 3600_000
        weekly_ms = int(self.cfg.scan.weekly_rescan_days) * 86400_000
        atrasados: list[tuple[int, str, int]] = []

        for ip in hosts:
            if ip == self.sensor_ip:
                continue
            if ip_excluded(ip, self.cfg.scan.exclude):
                continue
            device = store.get_device_by_ip(conn, ip)
            if device is None:
                continue
            device_id = int(device["id"])
            last = device["last_scan_ts"]
            if last is None:
                self._enqueue_scan(ScanJob(ip=ip, profile="standard", device_id=device_id),
                                   origin="auto")
                continue
            last_ok = store.last_scan_ts(conn, device_id, "standard")
            intento_std = store.last_scan_ts(conn, device_id, "standard", only_ok=False)
            confiable = device["estado_confianza"] == "confiable"
            # Un `standard` pendiente: el semanal de un equipo confiable o el
            # primer perfilado que no llegó a completarse (L-03), aunque el
            # equipo siga siendo desconocido.
            pendiente = last_ok is None and intento_std is not None
            if pendiente or (confiable and (last_ok is None or ts - last_ok > weekly_ms)):
                # El intento reciente sin resultado ya cuenta como backoff del
                # objetivo: un equipo que no responde no puede reescanearse en
                # cada barrido.
                if intento_std is not None and ts - intento_std <= quick_ms:
                    continue
                atrasados.append((last_ok or 0, ip, device_id))
                continue
            if ts - int(last) > quick_ms:
                self._enqueue_scan(ScanJob(ip=ip, profile="quick", device_id=device_id),
                                   origin="auto")

        if not atrasados:
            return
        presupuesto = max(1, int(self.cfg.scan.max_concurrent))
        for _ultimo, ip, device_id in sorted(atrasados):
            if presupuesto <= 0:
                break
            if self._enqueue_scan(ScanJob(ip=ip, profile="standard", device_id=device_id),
                                  origin="auto"):
                presupuesto -= 1

    # ------------------------------------------------------- detección pasiva
    def _on_neighbor(self, obs: Observation) -> None:
        """Un vecino nuevo o cambiado es evidencia de capa 2 en tiempo real."""
        if not ip_in_cidr(obs.ip_src, self.cfg.network.cidr):
            return
        if obs.ip_src == self.sensor_ip:
            return
        conn = self._conn()
        ts = obs.ts
        self._note_observation(NEIGH, ts)
        with self._lock:
            findings = self.engine.observe(obs)
        inv = Inventory(conn, self.cfg, self.oui, learning=baseline_status(conn)["learning"])
        if obs.extra.get("event") in ("new", "change"):
            findings.extend(inv.observe_host(obs.ip_src, obs.mac_src, ts, source="netlink"))
        self._persist(conn, findings, ts)

    def _sniff_loop(self) -> None:
        """Sniffer pasivo real; sólo se ejecuta en modo live."""
        from batrade.detect.sniffer import sniff_observations

        conn = self._conn()
        log.info("sniffer pasivo iniciado en %s", self.cfg.network.interface)

        def handle(obs: Observation) -> None:
            if self.stop_event.is_set():
                return
            self._note_observation(obs.kind, obs.ts)
            c = self._conn()
            with self._lock:
                findings = self.engine.observe(obs)
            if obs.kind == ARP and obs.ip_src and obs.mac_src:
                inv = Inventory(c, self.cfg, self.oui,
                                learning=baseline_status(c)["learning"])
                findings.extend(inv.observe_host(obs.ip_src, obs.mac_src, obs.ts,
                                                 source="sniff"))
            self._persist(c, findings, obs.ts)

        sniff_observations(self.cfg.network.interface, handle, self.stop_event)
        del conn

    # ------------------------------------------------------------- escaneos
    def _enqueue_scan(self, job: ScanJob, origin: str = "auto") -> bool:
        key = (job.ip, job.profile)
        with self._lock:
            if key in self._pending:
                return False
            self._pending.add(key)
        try:
            self.scan_queue.put_nowait(job)
            return True
        except queue.Full:
            with self._lock:
                self._pending.discard(key)
            log.warning("cola de escaneos llena; se descarta %s", job.ip)
            return False

    def _scan_worker(self) -> None:
        conn = self._conn()
        while not self.stop_event.is_set():
            try:
                job = self.scan_queue.get(timeout=0.5)
            except queue.Empty:
                continue
            if job is None:
                break
            key = (job.ip, job.profile)
            try:
                self._run_scan(conn, job)
            except Exception:
                log.exception("escaneo falló", extra={"fields": {"ip": job.ip}})
            finally:
                with self._lock:
                    self._pending.discard(key)

    def _run_scan(self, conn, job: ScanJob) -> None:
        ts = now_ms()
        if not ip_in_cidr(job.ip, self.cfg.network.cidr):
            log.warning("objetivo fuera de la subred: %s", job.ip)
            if job.request_id:
                store.close_scan_request(conn, job.request_id, "error", ts, "fuera del CIDR")
            return
        device = store.get_device_by_ip(conn, job.ip)
        device_id = job.device_id or (int(device["id"]) if device else None)
        scan_id = store.start_scan(conn, device_id, job.profile, job.profile,
                                   f"nmap {job.profile} {job.ip}", ts)
        _udp_ports, udp_note = udp_risky_ports(self.cfg, self.caps)
        if udp_note:
            # Una sola vez por ejecución de escaneo: el operador debe saber que
            # los puertos UDP del catálogo no se han podido verificar.
            log.info(udp_note)
        try:
            result = run_scan(self.cfg, job.ip, job.profile, self.caps)
        except TargetScanError as exc:
            # Fallo del objetivo (timeout o XML incompleto): nmap no está roto.
            # No toca tool_status; queda en `scans` con estado error y eso es lo
            # que frena el reintento inmediato de este equipo.
            error = f"{exc.motivo}: {exc.mensaje}"
            store.finish_scan(conn, scan_id, ts=now_ms(), estado="error", error=error)
            if job.request_id:
                store.close_scan_request(conn, job.request_id, "error", now_ms(), error)
            log.warning("escaneo de %s sin resultado (%s): %s", job.ip, exc.motivo, exc)
            return
        except ScanError as exc:
            failures = store.record_tool_status(conn, "nmap", now_ms(), False, error=str(exc))
            store.finish_scan(conn, scan_id, ts=now_ms(), estado="error", error=str(exc))
            if job.request_id:
                store.close_scan_request(conn, job.request_id, "error", now_ms(), str(exc))
            log.warning("nmap falló en %s: %s", job.ip, exc)
            for f in self._tool_failure_findings("nmap", str(exc), failures, now_ms()):
                self._persist(conn, [f], now_ms())
            return

        store.record_tool_status(conn, "nmap", now_ms(), True)
        store.finish_scan(conn, scan_id, ts=now_ms(), estado="ok",
                          xml_path=result.xml_path, exit_code=result.exit_code)
        if job.request_id:
            store.close_scan_request(conn, job.request_id, "hecho", now_ms())

        if device_id is None:
            return
        if result.hostnames:
            host = result.hostnames[0]
            conn.execute("UPDATE devices SET hostname = COALESCE(hostname, ?) WHERE id = ?",
                         (host[:63], device_id))
        diff = store.apply_scan_ports(conn, device_id, result.ports, now_ms(),
                                      self.cfg.scan.risky_ports,
                                      protocolos=result.protocols,
                                      perfil=job.profile)
        findings = self._scan_findings(conn, device_id, job, diff, result)
        self._persist(conn, findings, now_ms())

    def _scan_findings(self, conn, device_id: int, job: ScanJob, diff: dict,
                       result) -> list:
        from batrade.detect.observation import Finding

        device = store.get_device(conn, device_id)
        nombre = (device["alias"] or device["hostname"] or device["ip_actual"]
                  if device else job.ip)
        state = device["estado_confianza"] if device else "desconocido"
        out = []
        for p in diff["new_risky"]:
            out.append(Finding(
                tipo="port_risky", severidad="warn",
                clave=f"port:risky:{device_id}:{p['protocol']}:{p['port']}",
                ip_origen=device["ip_actual"] if device else job.ip,
                mac_origen=device["mac"] if device else None,
                detalle={
                    "resumen": (f"{nombre} expone el puerto {p['port']}/{p['protocol']} "
                                f"({p['service'] or 'servicio desconocido'})"),
                    "por_que": p["reason"],
                    "accion": ("Deshabilitar el servicio si no se usa, o aislar el "
                               "dispositivo en una VLAN de invitados."),
                    "puerto": p["port"], "protocolo": p["protocol"],
                    "servicio": p["service"], "version": p.get("version"),
                },
            ))
        for p in diff["new_ports"]:
            if state != "confiable":
                continue
            out.append(Finding(
                tipo="port_new", severidad="warn",
                clave=f"port:new:{device_id}:{p['protocol']}:{p['port']}",
                ip_origen=device["ip_actual"] if device else job.ip,
                mac_origen=device["mac"] if device else None,
                detalle={
                    "resumen": (f"Nuevo puerto {p['port']}/{p['protocol']} en {nombre}, "
                                "antes marcado como confiable"),
                    "por_que": "Un equipo de confianza abrió un servicio que no tenía.",
                    "accion": "Comprobar si es una actualización legítima o un compromiso.",
                    "puerto": p["port"], "protocolo": p["protocol"],
                },
            ))
        return out

    # --------------------------------------------------------------- replay
    def _feed_loop(self) -> None:
        conn = self._conn()
        if self.mode == "replay":
            path = self.pcap or self._default_pcap()
            if path is None:
                log.error("no hay pcap para replay; use --pcap o genere fixtures")
                return
            observations = scenarios.observations_from_pcap(path, speed=self.speed,
                                                            base_ts=now_ms())
            log.info("replay de %s (%d observaciones)", path, len(observations))
        else:
            name = self.scenario or "mixed"
            observations = scenarios.synthetic(name, self.cfg)
            log.info("simulación %s (%d observaciones)", name, len(observations))

        inv = Inventory(conn, self.cfg, self.oui, learning=baseline_status(conn)["learning"])
        previous = observations[0].ts if observations else 0
        for obs in observations:
            if self.stop_event.is_set():
                return
            gap = max(0, obs.ts - previous) / self.speed / 1000.0
            previous = obs.ts
            if gap > 0:
                if self.stop_event.wait(min(gap, 1.0)):
                    return
            feed = replace(obs, ts=now_ms())
            self._note_observation(obs.kind, feed.ts)
            with self._lock:
                findings = self.engine.observe(feed)
            if obs.kind == ARP and obs.ip_src and obs.mac_src and obs.ip_src != self.sensor_ip:
                findings.extend(inv.observe_host(obs.ip_src, obs.mac_src, feed.ts,
                                                 source=self.mode))
            self._persist(conn, findings, feed.ts)
        log.info("secuencia de %s completada", self.mode)

    def _default_pcap(self) -> str | None:
        fixtures = self.cfg.root / "fixtures" / "pcaps"
        candidate = fixtures / f"{self.scenario or 'mixed'}.pcap"
        return str(candidate) if candidate.exists() else None

    # ------------------------------------------------------------ persistencia
    def _persist(self, conn, findings: Iterable, ts: int) -> int:
        """Guarda hallazgos aplicando dedupe/cooldown y encolando notificaciones."""
        from batrade.events import persist_findings

        learning = baseline_status(conn)["learning"]
        out = persist_findings(
            conn, findings, self.cfg, ts, learning=learning,
            enqueue=lambda eid, t: self.notifier.enqueue(conn, eid, t),
        )
        for finding, event_id, is_new in out:
            if not (is_new and finding.needs_verify and self.cfg.detect.arp_verify):
                continue
            if not self.caps.raw_capture:
                # Sin CAP_NET_RAW no hay sonda posible: se deja constancia para
                # que el panel distinga "no verificable" de "sin respuesta".
                store.set_event_verified(conn, event_id, False, {
                    "verificacion": {
                        "estado": ESTADO_NO_VERIFICABLE,
                        "motivo": ("sin CAP_NET_RAW no se puede sondear ARP: la alerta se "
                                   "basa sólo en la evidencia pasiva"),
                    },
                    "macs_observadas": [],
                })
                continue
            self._spawn_verification(event_id, finding.needs_verify)
        return len(out)

    def _spawn_verification(self, event_id: int, ip: str) -> None:
        """Encola la sonda ARP sin bloquear la alerta (decisión C2).

        Un pool fijo de ``VERIFY_WORKERS`` hilos atiende la cola: los eventos
        siguen guardándose aunque la cola esté llena, y en ese caso sólo se
        pierde la comprobación (se registra en el log).
        """
        self._ensure_verify_pool()
        try:
            self._verify_queue.put_nowait((event_id, ip))
        except queue.Full:
            log.warning("cola de verificación llena; el evento %s queda sin verificar",
                        event_id)

    def _ensure_verify_pool(self) -> None:
        if self._verify_started:
            return
        with self._lock:
            if self._verify_started:
                return
            self._verify_started = True
            for i in range(VERIFY_WORKERS):
                t = threading.Thread(target=self._verify_worker,
                                     name=f"batrade-verify-{i}", daemon=True)
                self._threads.append(t)
                t.start()

    def _verify_worker(self) -> None:
        while not self.stop_event.is_set():
            try:
                item = self._verify_queue.get(timeout=0.5)
            except queue.Empty:
                continue
            if item is None:
                break
            event_id, ip = item
            try:
                self._run_verification(event_id, ip)
            except Exception:  # noqa: BLE001 - un fallo no puede tumbar el pool
                log.exception("verificación ARP falló", extra={"fields": {"evento": event_id}})

    def _run_verification(self, event_id: int, ip: str) -> None:
        """Sondea, interpreta y anota el resultado en el evento."""
        macs = probe_binding(ip, self.cfg.network.interface,
                             self.cfg.detect.arp_verify_timeout)
        confirmed, explanation = interpret(macs, self.engine.baseline.gateway_mac)
        estado = estado_verificacion(macs, confirmed)
        if estado in (ESTADO_CONFIRMADO, ESTADO_DESCARTADO):
            # Formato histórico del bloque (texto plano): no se cambia.
            verificacion: object = explanation
        else:
            verificacion = {"estado": estado, "motivo": explanation}
        conn = db.connect(self.cfg.paths.db)
        try:
            store.set_event_verified(conn, event_id, bool(confirmed),
                                     {"verificacion": verificacion,
                                      "macs_observadas": sorted(macs or [])})
        finally:
            conn.close()

    def _tool_failure_findings(self, tool: str, error: str, failures: int, ts: int) -> list:
        from batrade.events import tool_failure_findings
        return tool_failure_findings(tool, error, failures, ts)

    # ---------------------------------------------------------------- arranque
    def _log_startup(self) -> None:
        fields = {
            "mode": self.mode,
            "requested": self.cfg.sensor.mode,
            "iface": self.cfg.network.interface,
            "cidr": self.cfg.network.cidr,
            "raw": self.caps.raw_capture,
            "oui": len(self.oui),
        }
        log.info("batrade-sensor arrancando", extra={"fields": fields})
        for note in self.cfg.warnings:
            log.info("red: %s", note)
        for note in self.mode_notes:
            log.warning(note)
        for reason in self.caps.reasons:
            log.info("capacidad: %s", reason)


def cli_signal_handlers(stop_event: threading.Event) -> None:
    def handler(signum, _frame):
        log.info("señal %s recibida", signum)
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, handler)
        except (ValueError, OSError):
            pass
