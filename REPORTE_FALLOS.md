# Reporte de fallos y errores — Batrade Home-SOC

**Fecha:** 2026-11-22  
**Versión analizada:** 0.1.0  
**Base del análisis:** lectura completa del código fuente en `batrade/` + ejecución de la suite de tests

---

## Resultado de la suite de tests

```
plataforma linux — Python 3.14.10, pytest-9.2.0
314 tests recolectados · 314 passed · 0 failed · 0 errors
tiempo: 11.49 s
```

Todos los tests pasan. La columna **Cubierto por tests** en el resumen final indica si existe al menos un test que ejercite el camino de código del fallo. Que un test pase no contradice un fallo: varios de los problemas descritos aquí son condiciones de borde que los tests no alcanzan, o comportamientos correctos en el caso nominal pero incorrectos en el caso degradado.

---

## Estado actual (cierre de la fase 6)

Este informe se escribió con 314 tests y el código de `0.1.0` recién auditado.
Las secciones siguientes se conservan **como registro histórico del triaje**: no
se reescriben. Lo que sigue es el estado verificado hoy contra el árbol actual
(suite de 480 tests), hallazgo por hallazgo.

### Cerrados

| ID | Cómo se cerró | Dónde |
|----|---------------|-------|
| F-01 | `LocalSink` rota por tamaño (`max_mb`, `backups`) y escribe con permisos 600; un `OSError` no tumba la cola | `notify.py:149-173` |
| F-02 | Los hilos de verificación comparten `stop_event` y mueren con el sensor | `sensor.py:432-445`, `tests/test_verify_pool.py` |
| F-03 | Toda conexión fija `PRAGMA busy_timeout` y `journal_mode=WAL` al abrirse | `db.py:206-209` |
| F-04 | `probe_cidr` usa `selectors` (epoll) y cierra sockets en `finally` | `neigh.py:71-120` |
| F-05 | `safe_unlink_scan` valida que el fichero esté dentro de `var/scans` antes de borrar | `sensor.py:126`, usado por sensor y CLI |
| F-06 | `device_history` registra la IP por intervalo; la consulta filtra por dispositivo e IP vigente | `store.py:588-598` |
| R-03 | `process_once` cierra la conexión en `finally` | `notify.py:235-247` |
| R-05 | `table_counts` y `_reset_tables` validan los nombres contra `RESET_TABLES_ALL` | `store.py:737-767` |
| S-01 | `redactar()` en errores de canal, en el texto enviado y en `alerts.log` | `notify.py:130,144,168,263` |
| L-02 | El DHCP de `config.yaml` manda; sin config se aprende el primero y `doctor` avisa de que hay que fijarlo | `sensor.py`, `cli.py`, commit `85504ae` |
| L-03 | Se reencola el `standard` fallido con `last_scan_ts(only_ok=False)`, escalonado por `max_concurrent` | `sensor.py:612+` |
| D-01 | `_guard` cierra la conexión del hilo en `finally` (`_close_thread_conn`) | `sensor.py:346-361` |
| D-02 | `BEGIN IMMEDIATE` + `ROLLBACK` en `BaseException`, con test de migración mixta DDL+DML | `db.py:319-327`, `tests/test_migrations.py` |
| D-03 | `Sensor.__init__` cierra la conexión si falla a mitad de construcción | `sensor.py` |
| D-04 | `load_config` ya no llama a `ensure_dirs()`; la creación de directorios vive en los puntos de entrada (`cli`, `Sensor`, `create_app`, `demo`) | `config.py`, `cli.py`, `sensor.py`, `dashboard/app.py`, `demo.py`, `tests/test_config.py` |
| S-02 | `load_dotenv` no escribe en `os.environ`; los secretos viajan en `Config.secrets` (`repr=False`) hacia `Sensor._env()`, `DASHBOARD_TOKEN` y `redact.secretos_conocidos` | `config.py`, `sensor.py`, `redact.py`, `logging_setup.py`, `notify.py`, `tests/test_config.py` |
| L-04 | `apply_sweep` sólo acumula ausencias para equipos cuya `ip_actual` pertenece a `network.cidr` | `inventory.py`, `tests/test_inventory.py` |
| M-02 | `_human_age`, `_fmt_ago` y `_fmt_ts` comprueban `ms is None` en vez de `not ms`, tratando `0` como epoch válido | `dashboard/app.py`, `tests/test_panel_hardening.py` |
| M-03 | `/devices` pide `DEVICES_LIMIT + 1` y muestra un banner de aviso si el inventario queda truncado | `dashboard/app.py`, `dashboard/templates/devices.html`, `tests/test_panel_hardening.py` |
| M-04 | `parse_xml` sólo retira el `<!DOCTYPE nombre>` simple de nmap y usa `defusedxml(..., forbid_dtd=True)`, bloqueando subconjuntos internos y DTD externos | `net/nmap_scan.py`, `tests/test_parsers.py` |
| M-05 | `Sensor._env()` pasa sólo las variables que declara cada canal | `sensor.py:216-230` |

### Endurecimiento adicional (post-fase 6)

| Tema | Qué se corrigió | Dónde |
|------|-----------------|-------|
| BPF con motor de flujos | `sniff_observations` aplica `FLOW_FILTER` (`arp or (ip and (tcp or udp))`) cuando hay `on_packet`, y `observation_from_packet` descarta TCP sin flag `S` para no inflar observaciones de reglas | `detect/sniffer.py`, `detect/scenarios.py`, `tests/test_sniffer.py` |
| `reset-db` con logs rotados | El bucle de limpieza de `alerts.log.*` ya no sobrescribe `copia` (ruta del backup `.bak-reset-*`) | `cli.py`, `tests/test_reset_db.py` |
| `FlowEngine.emitted` acotada | Con `on_finding` no acumula copias en memoria; sin callback queda acotada a `EMITTED_MAX` | `flow/engine.py`, `tests/test_flow.py` |
| Panel web: Open Redirect y login CSRF | `_safe_redirect` valida `next`, `back` y `Referer`; `POST /login` exige CSRF e incluye el campo en `login.html` | `dashboard/app.py`, `dashboard/templates/login.html`, `tests/test_panel_hardening.py` |
| Redacción de `DASHBOARD_TOKEN` | Añadido a `VARIABLES_DE_CANAL` para que `redactar()` y los logs también lo tapen | `redact.py`, `tests/test_secrets.py` |
| Invariante SQL y cierre de conexiones | Todas las consultas SQL viven en `store.py`/`db.py` (verificado por test AST); `cmd_doctor`, `cmd_init`, `cmd_approve` y `cmd_export` cierran `conn` en `finally` | `store.py`, `cli.py`, `dashboard/app.py`, `inventory.py`, `sensor.py`, `demo.py`, `tests/test_project_metadata.py` |
| Docstring `_kmeans` | Alineado con su inicialización aleatoria uniforme (`rng.choice`) | `flow/scorer.py` |

### Mitigados o parciales

| ID | Estado |
|----|--------|
| R-04 | No reintenta netlink, pero `run()` degrada a sondeo TCP si el socket cae: la vigilancia no se queda muerta (`neigh.py:198-215`). |
| S-03 | Sigue siendo un Flask de desarrollo **a propósito**. Ahora el arranque fuera de loopback sin `DASHBOARD_TOKEN` se rechaza en config y en `--host`, y el acceso remoto es túnel SSH o proxy TLS con token (README, D-03). |

### Abiertos por decisión

| ID | Motivo |
|----|--------|
| R-02 | `except Exception` en `_scan_worker`: se deja como está; el worker debe sobrevivir a cualquier fallo. |
| S-04 | El token CSRF no rota: aceptado, no se cambia. |
| L-01 | `ArpBindingRule` no actualiza `prev.mac` del gateway: aceptado. |
| M-01 | `format_text` es texto plano (permisos 600 en `alerts.log`) y `format_telegram` escapa HTML con `html.escape`; no requiere cambio de código. |

### Corrección del análisis

- **R-01 no es un fallo.** El escenario descrito no se reproduce: no hay ningún
  `except:` desnudo en `batrade/`, y `except Exception` **no** captura
  `SystemExit` ni `KeyboardInterrupt` (derivan de `BaseException`). Lo que sí
  existe es la supervisión de hilos (`_guard`), que registra la muerte del hilo y
  alerta, que era el problema real detrás del hallazgo.

---

## Índice

1. [Fallos funcionales](#1-fallos-funcionales)
2. [Problemas de robustez y manejo de errores](#2-problemas-de-robustez-y-manejo-de-errores)
3. [Vulnerabilidades de seguridad](#3-vulnerabilidades-de-seguridad)
4. [Inconsistencias de lógica de negocio](#4-inconsistencias-de-lógica-de-negocio)
5. [Deuda técnica con impacto operacional](#5-deuda-técnica-con-impacto-operacional)
6. [Problemas menores y mejoras](#6-problemas-menores-y-mejoras)

---

## 1. Fallos funcionales

Problemas que producen comportamiento incorrecto o pérdida de datos en condiciones normales de operación.

---

### F-01 — `LocalSink.alerts.log` crece sin límite

**Archivo:** `batrade/notify.py`, clase `LocalSink`, método `write`

```python
with self.path.open("a", encoding="utf-8") as fh:
    fh.write(...)   # append indefinido
```

El archivo `var/alerts.log` se abre en modo append en cada alerta sin ningún mecanismo de rotación. La clase `LocalSink` no usa `RotatingFileHandler` ni comprueba el tamaño antes de escribir. En redes activas con muchos eventos este archivo puede llenar el disco y bloquear el sensor, que no captura la `OSError` resultante en la escritura.

**Impacto:** llenado de disco → bloqueo del proceso sensor.  
**Corrección:** reemplazar con `logging.handlers.RotatingFileHandler` o comprobar `path.stat().st_size` antes de escribir.

---

### F-02 — Los hilos de verificación ARP no reciben señal de parada

**Archivo:** `batrade/sensor.py`, método `_ensure_verify_pool`

```python
for i in range(VERIFY_WORKERS):
    t = threading.Thread(target=self._verify_worker, ...)
    self._threads.append(t)
    t.start()
```

Los hilos `batrade-verify-N` se añaden a `self._threads`, pero `Sensor.stop()` hace `join(timeout=3.0)` sobre todos los hilos. El problema: `_verify_worker` hace `self._verify_queue.get(timeout=0.5)` y comprueba `self.stop_event`, pero **nunca recibe un `None` sentinel** al parar (el `None` que pone `stop()` va a `self.scan_queue`, no a `_verify_queue`). En el código de `stop()`:

```python
try:
    self.scan_queue.put_nowait(None)   # solo la cola de escaneos
except queue.Full:
    pass
```

Los verificadores siguen vivos hasta que el `join(3 s)` expira, dejando hilos daemon que mueren abruptamente sin registrar la parada limpia.

**Impacto:** parada no limpia; sondas ARP en vuelo pueden escribir en la BD tras cerrar `self.conn`.  
**Corrección:** enviar `VERIFY_WORKERS` sentinels `None` a `_verify_queue` en `stop()`.

---

### F-03 — `_run_verification` abre una conexión nueva sin `WAL` ni `busy_timeout` coherentes

**Archivo:** `batrade/sensor.py`, método `_run_verification`

```python
conn = db.connect(self.cfg.paths.db)
try:
    store.set_event_verified(conn, event_id, ...)
finally:
    conn.close()
```

`db.connect` abre en modo lectura-escritura con `busy_timeout = 5000`. Sin embargo, esta conexión se abre en un hilo de verificación que puede coincidir en escritura con el hilo principal y los trabajadores de escaneo. El patrón es correcto en teoría (WAL + busy_timeout), pero si el `busy_timeout` expira mientras el sensor está bajo carga (muchas verificaciones simultáneas + escaneos), el `UPDATE` de verificación lanza `OperationalError: database is locked` que el `_verify_worker` captura con `except Exception` sin registrar el ID del evento afectado.

**Impacto:** eventos quedan con `verified = 0` de forma silenciosa sin que el operador sepa qué eventos no se verificaron.  
**Corrección:** capturar `sqlite3.OperationalError` explícitamente, registrar el `event_id` y el error específico en el log.

---

### F-04 — `probe_cidr` abre sockets TCP pero no garantiza el cierre en todos los caminos

**Archivo:** `batrade/net/neigh.py`, función `probe_cidr`

```python
for start in range(0, len(targets), concurrency):
    batch = targets[start:start + concurrency]
    socks: list[socket.socket] = []
    for ip in batch:
        sock = socket.socket(...)
        sock.setblocking(False)
        try:
            sock.connect((ip, port))
        except BlockingIOError:
            socks.append(sock)
        except OSError:
            sock.close()
            continue
    if socks:
        _, writable, errored = select.select([], socks, socks, timeout)
        ...
    for sock in socks:
        sock.close()
```

Si `select.select` lanza una excepción (p.ej. `select.error` por señal recibida durante la espera), el bucle `for sock in socks: sock.close()` nunca se ejecuta. Los descriptores de fichero quedan abiertos.

**Impacto:** fuga de descriptores de fichero; en redes grandes (`/16` = 65534 hosts) puede agotar el límite del proceso.  
**Corrección:** envolver `select.select` y el cierre en `try/finally`.

---

### F-05 — `_run_udp_pass` puede dejar el XML temporal si el rename falla

**Archivo:** `batrade/net/nmap_scan.py`, función `_run_udp_pass`

```python
udp_path = cfg.paths.scans_dir / f"scan-udp-{target}-{int(time.time() * 1000)}.xml"
...
finally:
    _safe_unlink(udp_path)
```

Si la función lanza antes de llegar al bloque `try` donde se parsea el XML (p.ej. `build_udp_argv` lanza `ScanError`), el `finally` del bloque interior no existe: el retorno temprano en `if not argv: return` antes del `try` hace que `_safe_unlink` nunca se llame si el archivo se creó parcialmente. En la práctica nmap no escribe el XML antes de terminar, pero si el proceso es interrumpido a mitad puede quedar un archivo `scan-udp-*.xml` huérfano fuera de la retención lógica de la BD.

**Impacto:** archivos XML huérfanos en `var/scans/` que no tienen entrada en `scans` y por tanto no se purgan en la retención.  
**Corrección:** mover `udp_path` fuera del flujo condicional y usar `try/finally` desde la asignación.

---

### F-06 — `events_for_device` puede devolver eventos de otro dispositivo con la misma IP

**Archivo:** `batrade/store.py`, función `events_for_device`

```python
return list(conn.execute(
    "SELECT * FROM events WHERE (ip_origen = ? OR ip_destino = ? OR mac_origen = ?) "
    "ORDER BY last_ts DESC LIMIT ?",
    (device["ip_actual"], device["ip_actual"], device["mac"], limit),
))
```

La consulta une por `ip_actual` sin considerar que una IP puede haber sido reasignada a otro dispositivo (campo `ip_actual` cambia con el tiempo). Si el dispositivo A tenía `192.168.1.10` y ahora lo tiene el B, el detalle del B mostrará eventos históricos del A.

**Impacto:** el detalle de un dispositivo muestra alertas que no le pertenecen, confundiendo al operador.  
**Corrección:** filtrar también por `first_seen`/`last_seen` del dispositivo, o unir a través de `device_history`.

---

## 2. Problemas de robustez y manejo de errores

Situaciones en las que el código puede fallar de formas difíciles de diagnosticar.

---

### R-01 — `except Exception` en `_guard` captura `SystemExit` y `KeyboardInterrupt` indirectamente

**Archivo:** `batrade/sensor.py`, método `_guard`

```python
def _guard(self, target):
    def runner():
        try:
            target()
        except Exception:
            log.exception("hilo %s terminó por excepción", ...)
    return runner
```

`Exception` no captura `SystemExit` ni `KeyboardInterrupt` directamente (son `BaseException`), pero sí captura `RuntimeError`, `ValueError` y cualquier otra excepción que no sea de base. El problema real es que si una biblioteca de terceros (p.ej. `scapy`) lanza una excepción que envuelve una señal del SO o un error de bajo nivel, el hilo muere silenciosamente sin que el sensor lo detecte. El log registra el traceback pero el sensor continúa funcionando con capacidad reducida sin alertar al operador de forma diferenciada (el evento `tool_failure` solo lo genera `_tool_failure_findings` a partir del tercer fallo consecutivo de una herramienta específica).

**Impacto:** un hilo clave como `batrade-sniff` o `batrade-sweep` puede morir sin que el operador reciba alerta inmediata.  
**Corrección:** tras registrar la excepción, emitir un evento `tool_failure` con severidad `crit` al morir un hilo de categoría crítica.

---

### R-02 — `_scan_worker` captura `Exception` genérica sin clasificar el tipo de fallo

**Archivo:** `batrade/sensor.py`, método `_scan_worker`

```python
try:
    self._run_scan(conn, job)
except Exception:
    log.exception("escaneo falló", extra={"fields": {"ip": job.ip}})
```

`_run_scan` ya maneja `TargetScanError` y `ScanError` internamente. Esta captura exterior es una red de seguridad, pero captura también errores de programación (`AttributeError`, `TypeError`) que deberían propagarse para ser detectados en desarrollo. En producción, un bug en `_run_scan` queda registrado en el log pero el sistema sigue funcionando sin señal visible.

**Impacto:** bugs en la lógica de escaneo pasan inadvertidos en producción.  
**Corrección:** capturar únicamente `(ScanError, sqlite3.OperationalError, OSError)` y dejar el resto propagar (o al menos emitir un evento `tool_failure` de mayor severidad).

---

### R-03 — `Notifier.process_once` abre una conexión pero no la cierra si `due_notifications` lanza

**Archivo:** `batrade/notify.py`, método `process_once`

```python
def process_once(self) -> int:
    ts = now_ms()
    conn = self.conn_factory()
    try:
        rows = store.due_notifications(conn, ts)
        ...
        return done
    finally:
        conn.close()
```

El patrón `try/finally` es correcto. El problema es que `self.conn_factory()` puede lanzar `sqlite3.OperationalError` si la BD está bloqueada, y esa excepción escapa del `try` sin que `conn.close()` se ejecute (porque `conn` no llegó a asignarse). En ese caso el `except Exception` del bucle `run()` captura la excepción, pero la conexión ya se perdió sin cerrarse.

En la práctica `conn_factory` es `lambda: db.connect(...)`, que falla antes de devolver la conexión, así que no hay fuga. Sin embargo el patrón es frágil: cualquier refactorización que haga que `conn_factory` devuelva parcialmente podría introducir la fuga.

**Corrección:** inicializar `conn = None` antes del `try` y proteger el `close` con `if conn is not None`.

---

### R-04 — `NeighborWatcher._run_netlink` no reintenta si el socket netlink se cierra inesperadamente

**Archivo:** `batrade/net/neigh.py`, método `_run_netlink`

```python
while not self.stop_event.is_set():
    try:
        data, _ = sock.recvfrom(65535)
    except socket.timeout:
        continue
    except OSError:
        raise    # cae al fallback de sondeo
```

Si el socket recibe un `OSError` (p.ej. la interfaz de red se desconecta y vuelve), el hilo cae al modo `_run_poll` para siempre, incluso si netlink vuelve a estar disponible. No hay reconexión automática.

**Impacto:** tras una reconexión de red el watcher pierde la eficiencia de netlink sin aviso, usando sondeo cada 2 s en lugar de eventos en tiempo real.  
**Corrección:** intentar reconectar el socket netlink tras un intervalo antes de degradar a sondeo permanente.

---

### R-05 — `store.table_counts` usa f-strings con nombres de tabla fijos, pero el patrón es arriesgado

**Archivo:** `batrade/store.py`, función `table_counts`

```python
for table in RESET_TABLES_ALL:
    row = conn.execute(f"SELECT COUNT(*) AS n FROM {table}").fetchone()
```

`RESET_TABLES_ALL` es una constante definida en el mismo archivo, así que actualmente no hay riesgo de inyección. Sin embargo el mismo patrón se repite en `_reset_tables`:

```python
for table in tables:
    counts[table] = conn.execute(f"DELETE FROM {table}").rowcount
```

donde `tables` es un parámetro de función. Si en el futuro se llama `_reset_tables` con una fuente externa de nombres de tabla, se introduce inyección SQL. El contrato no está documentado como "solo constantes internas".

**Corrección:** documentar explícitamente que `tables` debe ser siempre una constante del módulo, o validar cada nombre contra un conjunto permitido.

---

## 3. Vulnerabilidades de seguridad

---

### S-01 — El error HTTP de Telegram y Discord puede exponer fragmentos del token en el log

**Archivo:** `batrade/notify.py`, funciones `send_telegram` y `send_discord`

```python
raise NotificationError(f"Telegram HTTP {resp.status_code}: {resp.text[:200]}")
```

Si la API de Telegram responde con un cuerpo de error que incluye el token (p.ej. `{"description": "Unauthorized: bot token is invalid: bot<TOKEN>..."}`), esos 200 caracteres se escriben en el log de `batrade.log` (JSONL) con nivel `warning`. El log tiene permisos de archivo pero puede ser leído por cualquier proceso con acceso al directorio `var/`.

**Impacto:** filtración del token de Telegram en logs con permisos posiblemente más laxos que `.env`.  
**Corrección:** no incluir `resp.text` en el mensaje de error; solo registrar el código HTTP y, opcionalmente, un identificador de error sin credenciales.

---

### S-02 — `load_dotenv` escribe variables de entorno en el proceso (`os.environ.setdefault`)

**Archivo:** `batrade/config.py`, función `load_dotenv`

```python
os.environ.setdefault(key, val)
```

Las variables del `.env` se inyectan en el entorno del proceso. Cualquier subproceso lanzado después (nmap, arp-scan, ip) hereda `TELEGRAM_TOKEN`, `DISCORD_WEBHOOK`, etc., aunque no los use. Un subproceso comprometido (p.ej. un nmap troyanizado) puede leer el entorno completo.

**Impacto:** los secretos están disponibles para todos los subprocesos del sensor.  
**Corrección:** no usar `os.environ.setdefault`; en su lugar devolver el diccionario `values` sin modificar el entorno, y pasar los secretos explícitamente donde se necesiten (ya se hace en `Notifier` a través de `env=self._env()`). El problema es que `_env()` devuelve `dict(os.environ)`, que incluye los secretos igualmente.

---

### S-03 — El dashboard expone el servidor Flask de desarrollo en producción

**Archivo:** `batrade/cli.py`, función `cmd_dashboard`

```python
app.run(host=host, port=port, debug=False, use_reloader=False, threaded=True)
```

El proyecto usa el servidor integrado de Flask (`app.run`), que el propio Flask documenta como no apto para producción. Aunque `debug=False`, el servidor de desarrollo no soporta TLS, no tiene límites de concurrencia configurables ni protección ante ataques de denegación de servicio a nivel HTTP.

**Impacto:** bajo carga alta el dashboard puede volverse no responsivo o consumir todos los hilos disponibles.  
**Corrección:** documentar que para exposición en LAN se recomienda Gunicorn o uWSGI detrás de nginx. El README lo menciona indirectamente pero no de forma explícita en el contexto del dashboard.

---

### S-04 — `session["csrf"]` usa el mismo token durante toda la sesión sin rotación

**Archivo:** `batrade/dashboard/app.py`, función `_guard`

```python
if "csrf" not in session:
    session["csrf"] = secrets.token_urlsafe(18)
```

El token CSRF se genera una sola vez por sesión y nunca rota. Esto es el patrón "synchronizer token" estándar, pero sin rotación tras operaciones sensibles (cambiar el estado de un dispositivo, solicitar un escaneo `vuln`) un token robado de una sesión larga mantiene su validez.

**Impacto:** ventana de ataque CSRF más amplia en sesiones de larga duración.  
**Corrección:** rotar el token tras cada POST que realice una acción con efecto.

---

## 4. Inconsistencias de lógica de negocio

Comportamientos que divergen de lo que el operador razonablemente esperaría.

---

### L-01 — `ArpBindingRule` actualiza `prev.mac` solo cuando la IP no es el gateway

**Archivo:** `batrade/detect/rules.py`, clase `ArpBindingRule`

```python
prev.last_ts = obs.ts
if not is_gateway:
    prev.mac, prev.first_ts, prev.count = mac, obs.ts, 1
```

Cuando la IP sí es el gateway y la MAC cambia (lo que dispara un `arp_gateway_mac_change`), `prev.mac` no se actualiza: sigue apuntando a la MAC antigua. Si el router legítimo cambia de MAC (reinicio, failover), cada paquete ARP posterior del router legítimo seguirá disparando `arp_gateway_mac_change` repetidamente hasta que el `cooldown_s` lo detenga, aunque `baseline.gateway_mac` sí se actualice en el motor más adelante.

**Impacto:** falsos positivos repetidos tras un reinicio legítimo del router hasta que caduca el cooldown.  
**Corrección:** actualizar `prev.mac` también cuando `is_gateway`, igual que para las IPs no-gateway.

---

### L-02 — `DhcpRogueRule` aprende el primer servidor DHCP como legítimo sin verificación

**Archivo:** `batrade/detect/rules.py`, clase `DhcpRogueRule`

```python
expected = baseline.dhcp_server_ip
if not expected:
    baseline.dhcp_server_ip = server
    return []
```

Si el sensor arranca durante un ataque de DHCP rogue, o si un servidor DHCP ilegítimo responde antes que el legítimo, queda registrado como el esperado y el servidor real se alerta como "rogue". No hay mecanismo de confirmación ni comparación con `network.dhcp_server_ip` de la configuración.

**Impacto:** un atacante que active su servidor DHCP antes de que el sensor aprenda el legítimo queda catalogado como confiable permanentemente en esa sesión.  
**Corrección:** si `config.network.dhcp_server_ip` está definido, usarlo como única fuente de verdad en lugar de aprender dinámicamente.

---

### L-03 — `_schedule_scans` no reencola equipos que fallaron con `TargetScanError` si ya tienen `last_scan_ts`

**Archivo:** `batrade/sensor.py`, método `_schedule_scans`

```python
last = device["last_scan_ts"]
if last is None:
    self._enqueue_scan(ScanJob(..., profile="standard"), origin="auto")
    continue
```

`devices.last_scan_ts` se actualiza en `store.finish_scan` tanto para escaneos `ok` como para escaneos `error`. Si un dispositivo falla con `TargetScanError` (timeout), `last_scan_ts` se actualiza y el dispositivo nunca vuelve a recibir un escaneo `standard` automático (cae en la rama `quick` periódica). El mecanismo de backoff para equipos `confiable` sí usa `last_scan_ts(only_ok=False)`, pero los equipos `desconocido` o `no_autorizado` no tienen esa lógica.

**Impacto:** un equipo recién descubierto que falla su primer escaneo nunca recibe un nuevo escaneo `standard` automático, solo `quick` periódicos.  
**Corrección:** para equipos no `confiable`, verificar también si el último `standard` ok existe; si no, tratarlo como si no hubiera escaneo previo.

---

### L-04 — `apply_sweep` consulta `en_linea = 1` sin filtrar por interfaz

**Archivo:** `batrade/store.py` vía `batrade/inventory.py`, método `apply_sweep`

```python
rows = self.conn.execute("SELECT id FROM devices WHERE en_linea = 1").fetchall()
```

Si el sistema tiene varias interfaces monitoreadas (posible en configuraciones con múltiples CIDR) o si se cambia la interfaz entre reinicios, dispositivos de la red anterior pueden seguir marcados como `en_linea = 1`. El barrido de la nueva interfaz no los ve, acumula `misses` y los marca offline, lo que genera eventos `device_offline` para equipos que nunca estuvieron en esta red.

**Impacto menor** dado que el diseño actual soporta una sola interfaz, pero es una fuente de ruido al cambiar de red.

---

## 5. Deuda técnica con impacto operacional

Código que funciona hoy pero creará problemas a medida que el proyecto crezca.

---

### D-01 — `Sensor._local` (threading.local) puede acumular conexiones SQLite no cerradas

**Archivo:** `batrade/sensor.py`, método `_conn`

```python
def _conn(self):
    conn = getattr(self._local, "conn", None)
    if conn is None:
        conn = db.connect(self.cfg.paths.db)
        self._local.conn = conn
    return conn
```

Cada hilo abre una conexión SQLite y la almacena en `threading.local`. Las conexiones solo se cierran si el hilo termina limpiamente. Si un hilo muere por excepción (capturado en `_guard`), `self._local.conn` queda referenciado por el objeto `threading.local` del hilo muerto. En CPython el GC recogerá el objeto y SQLite cerrará la conexión en el destructor, pero no hay garantía de orden ni de momento.

**Impacto:** con muchos reinicios de hilos (en tests o tras fallos encadenados), pueden quedar múltiples conexiones WAL abiertas simultáneamente, lo que presiona el checkpoint.

---

### D-02 — `db.migrate` usa `BEGIN IMMEDIATE` pero la conexión es `isolation_level=None`

**Archivo:** `batrade/db.py`, función `migrate`

```python
conn.execute("BEGIN IMMEDIATE")
_run_migration(conn, steps)
conn.execute(f"PRAGMA user_version = {int(version)}")
conn.execute("COMMIT")
```

La conexión se abre con `isolation_level=None` (autocommit). Gestionar transacciones manualmente con `BEGIN`/`COMMIT`/`ROLLBACK` explícitos es correcto en este modo, pero mezclar `BEGIN IMMEDIATE` con la API de alto nivel de Python puede generar el error `cannot start a transaction within a transaction` si sqlite3 internamente inicia una transacción implícita. En la versión actual esto no ocurre porque todas las sentencias son DDL (`CREATE TABLE`, `CREATE INDEX`), que en SQLite no participan en transacciones implícitas de escritura. Sin embargo, una migración futura con `INSERT` o `UPDATE` podría introducir el problema.

---

### D-03 — `Sensor.__init__` hace trabajo de red y de BD que puede fallar sin cleanup

**Archivo:** `batrade/sensor.py`, método `__init__`

```python
self.conn = db.initialize(cfg.paths.db)
...
self.engine = Engine(cfg, self._load_baseline())
self.discovery = Discovery(cfg, self.caps)
self.notifier = Notifier(cfg, lambda: db.connect(cfg.paths.db), ...)
self._wire_sensor_identity()
```

Si `db.initialize` abre la conexión correctamente pero `_wire_sensor_identity` lanza (p.ej. porque la interfaz no existe), `self.conn` queda abierta sin que `__del__` o ningún gestor de contexto la cierre. El sensor no implementa `__enter__`/`__exit__` ni se usa como gestor de contexto.

**Impacto:** fuga de conexión SQLite si el constructor falla a mitad.  
**Corrección:** inicializar a `None` y proteger en `try/except` con cierre explícito, o implementar `__enter__`/`__exit__`.

---

### D-04 — `config.load_config` llama `cfg.ensure_dirs()` como efecto secundario de la validación

**Archivo:** `batrade/config.py`, función `load_config`

```python
cfg.ensure_dirs()
return cfg
```

Cargar la configuración crea directorios en disco. Esto hace que llamadas a `load_config` en tests (que solo quieren validar el YAML) tengan efectos en el sistema de ficheros. El propio test suite lo gestiona con fixtures temporales, pero es un efecto secundario no esperado de una función de "carga".

---

## 6. Problemas menores y mejoras

Aspectos de menor impacto pero que degradan la calidad del código o la experiencia operacional.

---

### M-01 — `format_text` y `format_telegram` no sanitizan el contenido de `detalle_json`

**Archivo:** `batrade/notify.py`

Los campos `resumen`, `por_que` y `accion` del `detalle_json` provienen del motor de reglas, que los construye con f-strings que incluyen datos de red (IPs, MACs, hostnames). Si un hostname contiene caracteres HTML (`<`, `>`), `format_telegram` usa `html.escape` sobre los campos fijos pero accede a `det.get(key)` sin escapar cuando los renderiza:

```python
parts.append(f"<b>{label}:</b> {e(str(det[key]))}")
```

Aquí `e` sí es `html.escape`, así que este caso está bien. Sin embargo `format_text` (texto plano) no escapa nada, lo que es correcto para texto plano. No hay problema real aquí, pero no está documentado.

---

### M-02 — `_human_age` devuelve `"nunca"` cuando `ms = 0`

**Archivo:** `batrade/dashboard/app.py`, función `_human_age`

```python
def _human_age(ms: int | None) -> str:
    if not ms:
        return "nunca"
```

El valor `0` (epoch) es falsy en Python, así que un timestamp almacenado como `0` se muestra como `"nunca"` en lugar de como una fecha real. Los timestamps de la BD son epoch en ms, y `0` podría aparecer en datos de migración o tests.

---

### M-03 — `store.list_devices` tiene un límite fijo de 500 no configurable desde el dashboard

**Archivo:** `batrade/store.py`, función `list_devices`

```python
def list_devices(..., limit: int = 500) -> list[sqlite3.Row]:
```

En redes con más de 500 dispositivos (posible en entornos corporativos pequeños), la vista `/devices` truncará silenciosamente el inventario sin indicárselo al usuario.

---

### M-04 — `parse_xml` elimina el DOCTYPE con regex pero la regex no es suficientemente robusta

**Archivo:** `batrade/net/nmap_scan.py`, función `parse_xml`

```python
raw = re.sub(rb"<!DOCTYPE[^>]*>", b"", raw, flags=re.IGNORECASE)
```

La regex `[^>]*` para después del primer `>`. Un DOCTYPE con un subconjunto interno (que nmap no genera pero podría aparecer en un XML manipulado) quedaría parcialmente eliminado. En la práctica nmap genera siempre el mismo DOCTYPE y `defusedxml` ya bloquea entidades externas, así que el riesgo es mínimo, pero la regex podría hacerse más robusta.

---

### M-05 — `Sensor._env()` devuelve el entorno completo del proceso

**Archivo:** `batrade/sensor.py`, método `_env`

```python
def _env(self) -> dict[str, str]:
    import os
    return dict(os.environ)
```

Este diccionario se pasa al `Notifier` para que resuelva los tokens. El entorno completo incluye variables del sistema (`PATH`, `HOME`, etc.) que no son secretos pero hacen el diccionario innecesariamente grande. No es un problema de seguridad porque `Notifier` solo lee las claves específicas que busca, pero es semánticamente incorrecto.

---

## Resumen por severidad

| ID | Título breve | Severidad | Cubierto por tests |
|----|-------------|-----------|-------------------|
| F-01 | `alerts.log` crece sin límite | Alta | No |
| F-02 | Hilos de verificación ARP sin sentinel de parada | Alta | Parcial — `test_verify_pool.py` cubre el pool pero no la parada limpia |
| F-03 | Verificación ARP falla silenciosamente bajo carga | Media | No |
| F-04 | `probe_cidr` fuga de descriptores en excepción | Media | No |
| F-05 | XML UDP temporal puede quedar huérfano | Baja | No |
| F-06 | `events_for_device` confunde dispositivos por IP reutilizada | Media | No |
| R-01 | Muerte de hilo crítico sin alerta al operador | Alta | No |
| R-02 | `except Exception` genérico en `_scan_worker` | Media | Parcial — `test_scan_target_failure.py` cubre `TargetScanError` y `ScanError` pero no errores de programación |
| R-03 | Conexión potencialmente no cerrada en `process_once` | Baja | No |
| R-04 | `NeighborWatcher` no reconecta netlink tras error | Baja | No |
| R-05 | Patrón f-string con nombres de tabla (riesgo futuro) | Baja | Sí — `test_reset_db.py` y `test_retention.py` ejercen las rutas afectadas |
| S-01 | Fragmentos del token Telegram en logs de error | Alta | No |
| S-02 | Secretos inyectados en entorno del proceso y subprocesos | Media | No |
| S-03 | Servidor Flask de desarrollo en producción | Media | No |
| S-04 | Token CSRF sin rotación post-acción | Baja | No |
| L-01 | `ArpBindingRule` no actualiza `prev.mac` del gateway | Media | No — `test_rules.py::test_gateway_mac_change_is_critical` detecta el primer cambio pero no el segundo |
| L-02 | Servidor DHCP rogue aprendido como legítimo en arranque | Alta | No — `test_rules.py::test_dhcp_server_is_learned_when_unknown` cubre el aprendizaje pero no el escenario de ataque en arranque |
| L-03 | Equipo sin escaneo `standard` tras `TargetScanError` | Media | Parcial — `test_scan_target_failure.py::test_standard_fallido_no_se_reintenta_en_cada_barrido` cubre el caso `confiable`; el caso `desconocido` no se prueba |
| L-04 | `apply_sweep` no filtra por interfaz | Baja | No |
| D-01 | Conexiones SQLite no cerradas en hilos muertos | Baja | No |
| D-02 | `BEGIN IMMEDIATE` frágil en migraciones futuras | Baja | Sí — `test_migrations.py` ejercita el runner pero no el caso mixto DDL+DML |
| D-03 | Constructor `Sensor` fuga conexión si falla a mitad | Baja | No |
| D-04 | `load_config` crea directorios como efecto secundario | Baja | Sí — el fixture `cfg` lo hace en `tmp_path`; el comportamiento está implícitamente aceptado |
| M-01 | Sanitización de `detalle_json` no documentada | Informativo | Sí — `test_notify.py::test_telegram_escapes_untrusted_text` |
| M-02 | `_human_age(0)` devuelve `"nunca"` | Informativo | No |
| M-03 | Límite de 500 dispositivos sin aviso en `/devices` | Informativo | No |
| M-04 | Regex DOCTYPE no robusta ante subconjuntos internos | Informativo | No |
| M-05 | `_env()` expone entorno completo al Notifier | Informativo | No |

**Altas:** 4 — **Medias:** 8 — **Bajas:** 10 — **Informativos:** 5

---

## Gaps de cobertura identificados en los tests

La suite cubre bien los caminos nominales: dedupe de eventos, retención, política de cierre de puertos, scheduling de escaneos, verificación ARP, pool de concurrencia y el comportamiento ante XML truncado. Los siguientes caminos no tienen tests y corresponden a fallos documentados arriba.

### Sin ningún test

| Camino sin cubrir | Fallo asociado |
|---|---|
| `LocalSink.write` cuando el disco está lleno o el archivo es muy grande | F-01 |
| `Sensor.stop()` enviando sentinels a `_verify_queue` | F-02 |
| `_run_verification` con `OperationalError` por BD ocupada | F-03 |
| `probe_cidr` cuando `select.select` lanza excepción | F-04 |
| `_run_udp_pass` con ruta de retorno temprano antes del `try` | F-05 |
| `events_for_device` con IP reutilizada entre dos dispositivos | F-06 |
| Hilo `batrade-sniff` o `batrade-sweep` muriendo por excepción | R-01 |
| `NeighborWatcher` tras `OSError` en `recvfrom` intentando reconectar | R-04 |
| `Notifier.process_once` cuando `conn_factory` lanza | R-03 |
| Respuesta de error de Telegram con token en el cuerpo | S-01 |
| `Sensor.__init__` fallando después de `db.initialize` | D-03 |
| `ArpBindingRule` con segundo cambio de MAC del gateway | L-01 |
| Servidor DHCP rogue respondiendo antes que el legítimo en arranque | L-02 |
| `_schedule_scans` con dispositivo `desconocido` tras `TargetScanError` | L-03 |
| `_human_age` con valor `0` | M-02 |

### Parcialmente cubiertos

- **F-02 / `test_verify_pool.py`:** los cuatro tests del pool verifican concurrencia, idempotencia, cola llena y supervivencia ante excepciones de la sonda. Ninguno verifica que al llamar `Sensor.stop()` los `VERIFY_WORKERS` hilos terminen limpiamente (el test de parada en `test_sensor_stop.py` usa un sensor bare sin pool de verificación).

- **L-03 / `test_scan_target_failure.py::test_standard_fallido_no_se_reintenta_en_cada_barrido`:** solo prueba un dispositivo `confiable`. La rama de `_schedule_scans` que maneja dispositivos `desconocido` con `last_scan_ts` tras un error no se prueba.

- **R-02 / `test_scan_target_failure.py`:** cubre `TargetScanError` (timeout, XML truncado) y `ScanError` (nmap roto). No cubre errores de programación como `AttributeError` o `TypeError` dentro de `_run_scan`, que el `except Exception` exterior silenciaría.
