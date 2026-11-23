# Política de seguridad — Batrade Home-SOC

Batrade es un SOC doméstico que se ejecuta con privilegios sobre la red de casa:
sniffer en modo promiscuo, escaneos nmap/arp-scan, panel web y notificaciones.
Un fallo aquí no es un bug cosmético: puede exponer el inventario de la red,
ejecutar código como root o tirar la vigilancia sin que nadie se entere.

## Cómo reportar

- **Correo:** `jjangel2815@gmail.com`, asunto `[SECURITY] Batrade: <resumen corto>`.
  Es la dirección del mantenedor; si en el futuro hay un alias dedicado, se
  publicará aquí y en el README.
- **No abras un issue público** ni un PR con el detalle del fallo, ni lo publiques
  en redes. El repositorio no tiene todavía un canal privado de GitHub
  (Security Advisories); el correo es el canal oficial.
- **Qué incluir:** versión o commit (`git rev-parse --short HEAD`), sistema y
  versión de Python, modo del sensor (`privileged` / `degraded`), pasos para
  reproducir, impacto que le ves y, si tienes PoC, el mínimo que lo demuestre.
  **No adjuntes datos reales** de tu red: usa MAC/IP de ejemplo (`10.10.10.0/24`,
  `3c:22:fb:11:22:33`) y una base temporal.
- **Cifrado:** si prefieres cifrar el reporte, pide la clave por correo en un
  primer mensaje sin detalles; no hay huella publicada todavía.

## Qué se considera vulnerabilidad

Dentro de alcance:

- **Bypass de autenticación o de sesión** del panel (`DASHBOARD_TOKEN`, cookie de
  sesión, CSRF en las rutas de escritura).
- **Ejecución de código o de comandos**: inyección en los argumentos de nmap o
  arp-scan, `shell=True` en cualquier camino, deserialización de datos no
  confiables (el modelo de flujos se carga con `numpy`, nunca con `pickle`).
- **Inyección SQL** o cualquier SQL que no viva en `store.py`/`db.py`.
- **Exposición de datos**: leer eventos, dispositivos o el inventario sin sesión
  válida; que el panel sirva datos a otro origen; que `/api/live` filtre más de
  lo que la vista permite.
- **Fuga de secretos** (`TELEGRAM_TOKEN`, `DASHBOARD_TOKEN`, `DISCORD_WEBHOOK`)
  en logs, notificaciones, mensajes de error o el HTML del panel.
- **XSS o inyección de marcado** con datos de red (hostnames, banners de nmap,
  nombres de fabricante son **no confiables** por definición).
- **Path traversal** en el manejo de XML de nmap, exportaciones o rutas de
  `var/scans`.
- **Denegación de servicio local**: una ruta del panel que bloquee el sensor, o
  entradas de configuración que agoten memoria/descriptores.
- **Elevación de privilegios** a través del instalador, las units de systemd o
  el wrapper de `batrade`.

Fuera de alcance (conocido y aceptado, no hace falta reportarlo):

- **El panel es un servidor de desarrollo Flask a propósito.** No tiene TLS ni
  límites de peticiones propios: por diseño se queda en `127.0.0.1` y se accede
  por túnel SSH o por un reverse proxy TLS con `DASHBOARD_TOKEN`. "Se puede
  exponer `:8000` a la red" no es una vulnerabilidad del código: es un error de
  despliegue, y el README explica cómo no hacerlo. Si aun así encuentras una
  forma de saltarte el rechazo de arranque fuera de loopback sin token, **eso sí
  es un fallo** y queremos saberlo.
- Ausencia de rate limiting, de WAF y de cabeceras de seguridad HTTP más allá de
  las que ya pone el panel.
- Hallazgos ya documentados y triados en `REPORTE_FALLOS.md` (incluidos los
  aceptados sin cambio, como la rotación del token CSRF o el `except Exception`
  del worker de escaneo) mientras no aportes un escenario nuevo que los agrave.
- Fallos de terceros: `scapy`, `nmap`, `arp-scan`, `Flask`, `numpy`. Repórtalos
  aguas arriba; si Batrade los empeora, entonces sí.
- Ataques que ya requieren root o acceso físico a la máquina del sensor.

## Política de divulgación

| Plazo | Compromiso |
|---|---|
| 72 h | Acuse de recibo con un identificador de seguimiento |
| 7 días | Primera evaluación: confirmado, descartado o falta información |
| 30 días | Corrección o mitigación para críticas y altas |
| 90 días | Corrección o mitigación para el resto |

- **No se divulga públicamente hasta que haya corrección publicada**, y en todo
  caso no antes de 7 días después del fix para dar tiempo a actualizar.
- Si el fallo está siendo explotado, se publica un aviso con mitigaciones antes
  del fix completo.
- Se avisa al reportero antes de publicar y se le acredita si lo quiere (nombre
  o seudónimo, a elección).
- Si no hay acuerdo sobre los plazos, el reloj de 90 días manda: pasado ese
  plazo el reportero puede publicar, y se pedirá que incluya las mitigaciones
  disponibles.

## Versiones soportadas

Sólo la última versión del repositorio (`main`) y la última instalación
publicada como `0.1.x`. No hay ramas de mantenimiento: la corrección se aplica
en `main` y se instala con el instalador.

## Nota sobre el despliegue

El panel y el sensor están pensados para una máquina dedicada en la LAN:

- El panel escucha en `127.0.0.1:8000` y **no debe exponerse directamente**.
  Fuera de loopback exige `DASHBOARD_TOKEN` y, aun con token, la vía correcta es
  `ssh -L 8000:127.0.0.1:8000 usuario@host-del-sensor` o un reverse proxy con
  TLS delante (README, «Remote access to the panel»).
- El sensor necesita `CAP_NET_RAW` y `CAP_NET_ADMIN`; el usuario del panel no.
- La base SQLite, `.env`, `config.yaml` y `var/` no se publican ni se comparten:
  contienen inventario y secretos de la red.

## Reconocimiento

Gracias por reportar en privado. Un fallo bien explicado vale más que un escaneo
de 500 páginas: con versión, pasos y una base de ejemplo se arregla en horas.
