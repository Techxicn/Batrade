# Changelog

Todos los cambios notables de **Batrade Home-SOC** se documentan en este archivo.
El formato sigue [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/) y las versiones siguen [Versionado Semántico](https://semver.org/lang/es/).

## [Unreleased]

### Cambiado
- **Tema «Fósforo» en el panel web** (`batrade/dashboard/static/style.css`): estética de terminal con tipografía monoespaciada, esquinas rectas, navegación en vídeo inverso y etiquetas de severidad entre corchetes. Todos los colores pasan a variables de `:root` (contraste AA comprobado) y las ligaduras tipográficas se desactivan para que IPs, MACs y textos de red se lean tal cual.
- **Barra de severidad del día en `/`**: sustituye a las tarjetas «Alertas hoy» y «Falsos positivos hoy»; cada tramo (crítico, advertencia, informativo) crece en proporción a su recuento y `live.js` la refresca en cada sondeo, con singular/plural y etiqueta accesible.
- Cabecera de página en `/` con la red, la interfaz y el estado de la línea base, y la hora del último sondeo correcto.
- Las tablas anchas de `/`, `/devices` y `/events` se desplazan dentro de su recuadro en pantallas estrechas.

### Añadido
- Fuente **JetBrains Mono** (SIL OFL 1.1) servida desde `batrade/dashboard/static/fonts/` con su licencia y declarada en `package-data`: el panel sigue funcionando sin internet.
- `tests/test_dashboard_theme.py`: barra de severidad, recursos locales del CSS, fuente empaquetada y servida sin sesión.

## [0.1.0] - 2026-11-25

Primera versión pública bajo **licencia MIT**.

### Añadido
- **Sensor pasivo multihilo** (`batrade/sensor.py`) con cinco modos (`auto`, `live`, `degraded`, `replay`, `simulate`), supervisión de hilos críticos con reintentos exponenciales y observabilidad de captura (`capture_idle`).
- **Descubrimiento e inventario** (`batrade/net/`, `batrade/inventory.py`): barrido con `arp-scan` o degradación automática a `probe_cidr` (`selectors`) + `ip neigh` + `NETLINK_ROUTE`, agrupación de MACs aleatorias por hostname, modo aprendizaje y aprobación de línea base.
- **Perfilado con nmap** (`batrade/net/nmap_scan.py`): perfiles `quick`, `standard` y `vuln`, pasada UDP acotada con `CAP_NET_RAW` (`1900/udp` UPnP/SSDP, `5353/udp` mDNS), `scan.exclude`, política estricta de cierre de puertos y diferenciación entre fallos de objetivo y de herramienta.
- **Motor de reglas de detección** (`batrade/detect/`): ARP spoofing (con verificación ARP activa en pool acotado), ARP sweep, ARP flood con conflicto real, escaneo SYN (puertos y hosts) y servidor DHCP rogue con prioridad de configuración.
- **Motor de anomalías por flujos (opt-in)** (`batrade/flow/`, `scripts/train_baseline.py`): colector bidireccional en ventanas temporales, Isolation Forest y segmentador K-Means en NumPy puro (extra `[ml]`, sin `pickle`), con filtro BPF dedicado (`FLOW_FILTER`) cuando está activo.
- **Notificaciones con cola persistente** (`batrade/notify.py`): canales `local` (con rotación por tamaño y permisos `600`), Telegram y Discord usando `urllib.request` (sin dependencia externa `requests`), backoff exponencial y redacción de secretos (`batrade/redact.py`).
- **Panel web en vivo** (`batrade/dashboard/`): interfaz SSR en Flask sobre SQLite WAL con sondeo de sólo lectura (`GET /api/live` por cursor), pop-ups, sonido sintetizado Web Audio, notificaciones del navegador, autenticación por `DASHBOARD_TOKEN`, protección CSRF (incluido `/login`), validación contra open redirect y aviso de truncado en `/devices`.
- **Persistencia y mantenimiento** (`batrade/db.py`, `batrade/store.py`, `batrade/cli.py`): esquema SQLite versionado (`v2`) con migraciones transaccionales y copias de seguridad previas (`600`), retención horaria con limpieza de XML huérfanos y comando `reset-db` sólo por CLI con root.
- **Instalación, despliegue y CI**: `install.sh` multi-distro (`apt`, `dnf`, `pacman`, `zypper`, `apk`) con modo `--system`, soporte multi-VLAN y `--uninstall`/`--purge`, unidades `systemd` endurecidas (`deploy/`), suite offline de pruebas en Ubuntu (Python 3.11, 3.12, 3.13) y linting con `ruff`.
- **Documentación y gobernanza**: `LICENSE` (MIT), `SECURITY.md`, `CONTRIBUTING.md`, `REPORTE_FALLOS.md` y `README.md`.
