# Cómo contribuir a Batrade

Batrade es un SOC doméstico: IDS de sólo detección, con sensor en Python
(`scapy`, `nmap`, `arp-scan`), panel Flask y notificaciones. Antes de escribir
código, dos reglas del proyecto:

- **Las decisiones de arquitectura viven en `DECISIONS.md`** (D-01…D-12). Es la
  fuente de verdad: si una propuesta contradice una decisión cerrada, se reabre
  la decisión en el mismo cambio, no se ignora en el código. Hoy ese fichero no
  está versionado; si no lo tienes, las decisiones que afecten a tu cambio se
  citan (D-xx) y se explican en el PR.
- **Un cambio, una fase, un commit.** Nada de commits que mezclan refactor,
  feature y limpieza.

## Entorno

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'          # + '.[ml]' si tocas el motor de flujos
.venv/bin/python -m pip install -e '.[dev,ml]'       # las dos cosas
```

Se requiere Python ≥ 3.11 (probado en 3.11, 3.12 y 3.13 en CI). Opcional en el
sistema: `nmap`, `arp-scan`, `iproute2`; `bash install.sh --install-deps` los
instala con el gestor de la distribución.

## Tests

```bash
.venv/bin/python -m pytest                 # suite completa (≈480 tests, <60 s)
.venv/bin/python -m pytest tests/test_flow.py -q
.venv/bin/python -m pytest -k "panel and not slow"
```

Los tests son **offline y sin privilegios**: no abren la red real, no usan
`sudo`, no tocan `var/`, `.env` ni datos de un sensor en marcha. Usan bases
temporales (`tmp_path`), observaciones sintéticas y las fixtures de
`fixtures/pcaps/` y `fixtures/nmap/`. Si un test necesita red o root, está mal
planteado: pide un mock o una fixture.

Antes de enviar un cambio, como mínimo:

```bash
.venv/bin/python -m pytest                 # verde
.venv/bin/python -m pytest --collect-only | tail -1   # cuántos tests hay ahora
```

## Invariantes que no se rompen

1. **Todo el SQL vive en `batrade/store.py` y `batrade/db.py`.** Una consulta
   suelta en una vista o en el motor de reglas es un cambio rechazado.
2. **Timestamps en milisegundos UTC**, siempre (`now_ms()`), nunca `datetime`
   naive ni segundos.
3. **Nunca `shell=True`.** Los comandos externos se lanzan con listas de
   argumentos y con los objetivos validados como IPv4.
4. **XML siempre con `defusedxml`**, nunca con `xml.etree` sobre entrada ajena.
5. **El panel es de sólo lectura** salvo alias/confianza, `scan_requests` y
   `events.disposicion`. Cualquier ruta nueva de escritura necesita CSRF,
   sesión y test.
6. **Sin cambios de esquema sin migración probada.** Cada migración va con su
   test (incluido el caso mixto DDL+DML).
7. **Sin dependencias nuevas** sin justificarlo en el PR y actualizar
   `pyproject.toml`. `numpy` es opcional (`[ml]`): el paquete debe importarse y
   funcionar sin él.
8. **Los datos de red no son confiables** (hostnames, banners): se escapan al
   pintarlos en HTML y al mandarlos a Telegram.

## Estilo

- **Español** en código, comentarios, mensajes de operador, tests y commits;
  identificadores en español cuando describen dominio (`dispositivo`, `hallazgo`,
  `barrido`), en inglés cuando son genéricos (`handler`, `payload`).
- **Commits en imperativo**, en español, un cambio por commit: `Añade exclusión
  de objetivos`, `Corrige la rotación de alerts.log`, `Documenta el túnel SSH`.
  Sin `feat:`/`fix:` obligatorio, sin commits de "varios arreglos".
- **Nada de `print` para diagnosticar** en código de producción: `logging` con
  el logger del módulo (`batrade.sensor`, `batrade.dashboard`, …).
- Comentarios que expliquen **por qué**, no qué hace la línea.

## Cómo proponer un cambio

1. **Issue primero** para cambios de arquitectura, de esquema, de seguridad o
   que toquen más de dos módulos. Un PR grande sin issue previo suele acabar en
   discusión de diseño en vez de revisión.
2. **Rama por fase**: `feat/<tema>`, `fix/<tema>`, `docs/<tema>`.
3. **PR con:** qué problema resuelve, qué decisión (D-xx) lo ampara o cuál hay
   que añadir, los tests nuevos, y el resultado de `pytest`. Si cambia
   comportamiento visible, actualiza README y `DECISIONS.md`.
4. **No mezcles** refactor con cambio funcional: si el refactor hace falta,
   primero, en su propio commit.
5. **Vulnerabilidades:** no abras issue ni PR público. Lee `SECURITY.md` y
   escribe a `jjangel2815@gmail.com`.

## Qué NO se acepta en este proyecto

- Detección **activa** contra terceros (bloqueo, cortafuegos, ARP poisoning):
  Batrade detecta y avisa, no interviene la red.
- Telemetría, analítica o llamadas a servicios externos que no sean los canales
  de notificación que el operador configura.
- Cualquier cosa que exponga el panel fuera de loopback sin `DASHBOARD_TOKEN`;
  la validación de configuración y la CLI lo rechazan a propósito.
- Código generado sin revisar, dependencias con licencia incompatible con la del
  proyecto (ver D-12) y ficheros binarios grandes.

## Licencia de las contribuciones

Batrade se distribuye bajo la **licencia MIT** (`LICENSE`). Al enviar una
contribución (PR o parche), aceptas que quede cubierta por la misma licencia
MIT del proyecto. Recuerda que `scapy` es **GPL-2.0-only**: no se copia código
suyo en este árbol; se mantiene siempre como dependencia externa.
