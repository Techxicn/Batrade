#!/usr/bin/env bash
# Batrade Home-SOC — instalación y verificación multi-distribución.
#
# Modos:
#   (sin opciones)      comprueba el entorno del repositorio y crea la base
#   --system            instala en el sistema (root) y deja `batrade` en el PATH
#   --uninstall         quita el código y el comando; conserva var/, .env, config.yaml
#
# Cubre Debian/Ubuntu/Kali/Parrot (apt), Fedora/RHEL/Rocky/Alma (dnf),
# Arch/BlackArch (pacman), openSUSE (zypper) y Alpine (apk).
#
# Modo repositorio: --install-deps, --venv, --systemd, --link
# Modo sistema:     --prefix DIR, --start, --dry-run
# Acceso remoto:    --proxy (sólo imprime la receta del reverse proxy TLS)
# Desinstalación:   --uninstall [--purge] [--yes] [--dry-run]
#
# Variables de entorno:
#   BATRADE_BIN_DIR     directorio del comando `batrade` (defecto /usr/local/bin).
#                       Con una instalación por VLAN, dale uno distinto a cada una
#                       (p. ej. /opt/batrade-vlan10/bin) para que no se pisen.
#   BATRADE_TEST_FAKE_ROOT=1   sólo pruebas: no exige root.
#
# No hace nada destructivo: comprueba, informa e inicializa la base de datos.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
PY="${PYTHON:-python3}"
INSTALL_DEPS=0
USE_VENV=0
INSTALL_SYSTEMD=0
LINK_BIN=0
SYSTEM=0
PREFIX="/opt/batrade"
START_AFTER=0
DRY_RUN=0
UNINSTALL=0
PURGE=0
SHOW_PROXY=0
ASSUME_YES=0

usage() {
    awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "${BASH_SOURCE[0]}"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --install-deps) INSTALL_DEPS=1 ;;
        --venv) USE_VENV=1 ;;
        --systemd) INSTALL_SYSTEMD=1 ;;
        --link) LINK_BIN=1 ;;
        --system) SYSTEM=1 ;;
        --start) START_AFTER=1 ;;
        --dry-run) DRY_RUN=1 ;;
        --proxy) SHOW_PROXY=1 ;;
        --uninstall) UNINSTALL=1 ;;
        --purge) PURGE=1 ;;
        --yes|-y) ASSUME_YES=1 ;;
        --prefix)
            [[ $# -ge 2 ]] || { echo "ERROR: --prefix necesita un directorio" >&2; exit 2; }
            PREFIX="$2"
            shift
            ;;
        --prefix=*) PREFIX="${1#*=}" ;;
        -h|--help) usage; exit 0 ;;
        *) echo "opción desconocida: $1" >&2; exit 2 ;;
    esac
    shift
done


# --------------------------------------------------------------------------- #
# --proxy: receta del reverse proxy TLS. No instala nada y no necesita root.
# --------------------------------------------------------------------------- #
do_proxy() {
    cat <<'EOF'
== Batrade · reverse proxy TLS delante del panel ==

No se instala nada: sólo se imprime la receta. El panel sigue escuchando en
127.0.0.1:8000; el proxy es el único que publica un puerto (443) y termina TLS.

1) Token obligatorio. Sin DASHBOARD_TOKEN el panel no arranca fuera de loopback:

     openssl rand -hex 32
     # edita el .env del usuario que corre el panel y añade:
     #   DASHBOARD_TOKEN=<los 64 caracteres hexadecimales>
     chmod 600 .env
     sudo systemctl restart batrade-dashboard     # o: batrade stop && batrade start

2) Caddy (/etc/caddy/Caddyfile):

     panel.example.lan {
         reverse_proxy 127.0.0.1:8000
     }

3) Nginx equivalente (/etc/nginx/conf.d/panel.conf):

     server {
         listen 443 ssl;
         server_name panel.example.lan;
         ssl_certificate     /etc/ssl/certs/panel.crt;
         ssl_certificate_key /etc/ssl/private/panel.key;
         location / {
             proxy_pass http://127.0.0.1:8000;
             proxy_set_header Host $host;
             proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
         }
     }

Recuerda: el Flask es un servidor de desarrollo. NUNCA publiques :8000; el
único puerto abierto debe ser el 443 del proxy. Sin proxy, el método oficial
es el túnel SSH:

     ssh -L 8000:127.0.0.1:8000 usuario@host-del-sensor
EOF
}

say() { printf '  %-12s: %s\n' "$1" "$2"; }
die() { echo "ERROR: $*" >&2; exit 1; }
plan() { printf '  %-12s: [dry-run] %s\n' "plan" "$*"; }
run() {
    if ((DRY_RUN)); then
        plan "$*"
        return 0
    fi
    "$@"
}

# --proxy sale antes de todo lo demás: ni root, ni prefijo, ni
# comprobaciones del entorno. Sólo imprime la receta.
if ((SHOW_PROXY)); then
    do_proxy
    exit 0
fi

require_root() {
    if [[ $EUID -eq 0 ]]; then
        return 0
    fi
    if [[ "${BATRADE_TEST_FAKE_ROOT:-0}" == "1" ]]; then
        say "aviso" "BATRADE_TEST_FAKE_ROOT=1: no se comprueba root (sólo pruebas)"
        return 0
    fi
    echo "ERROR: esta operación necesita privilegios de administrador." >&2
    echo "       Ejecuta con sudo: sudo bash install.sh $*" >&2
    exit 1
}

# confirm_word "<pregunta>" "<palabra exacta>": exige escribir la palabra.
confirm_word() {
    local pregunta="$1" esperada="$2" respuesta=""
    if ((ASSUME_YES)); then
        return 0
    fi
    if [[ ! -t 0 ]]; then
        echo "ERROR: no hay terminal interactiva; repite con --yes" >&2
        return 1
    fi
    read -r -p "$pregunta " respuesta
    [[ "$respuesta" == "$esperada" ]]
}

# --------------------------------------------------------------------------- #
# Distribución y gestor de paquetes (compartido por ambos modos)
# --------------------------------------------------------------------------- #
PM=""
PKGS=""
INSTALL_CMD=()

pm_binary() {
    case "$1" in
        apt) echo apt-get ;;
        dnf) echo dnf ;;
        pacman) echo pacman ;;
        zypper) echo zypper ;;
        apk) echo apk ;;
        *) echo "" ;;
    esac
}

detect_distro() {
    DISTRO="Linux"
    DISTRO_IDS=""
    if [[ -r /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        DISTRO="${PRETTY_NAME:-${NAME:-Linux}}"
        DISTRO_IDS="${ID:-}${ID_LIKE:+ $ID_LIKE}"
    fi

    # El gestor se decide por la distribución (ID/ID_LIKE) antes que por
    # binarios sueltos: en Fedora puede existir `apt` a mano y no ser el bueno.
    PM=""
    case " ${DISTRO_IDS} " in
        *" debian "*|*" ubuntu "*|*" kali "*|*" parrot "*|*" linuxmint "*|*" pop "*) PM=apt ;;
        *" fedora "*|*" rhel "*|*" centos "*|*" rocky "*|*" almalinux "*) PM=dnf ;;
        *" arch "*|*" archlinux "*|*" blackarch "*|*" manjaro "*) PM=pacman ;;
        *" opensuse "*|*" suse "*|*" sles "*) PM=zypper ;;
        *" alpine "*) PM=apk ;;
    esac
    if [[ -z "$PM" || -z "$(command -v "$(pm_binary "$PM")" 2>/dev/null || true)" ]]; then
        PM=""
        for candidate in apt dnf pacman zypper apk; do
            if command -v "$(pm_binary "$candidate")" >/dev/null 2>&1; then
                PM="$candidate"
                break
            fi
        done
    fi

    case "$PM" in
        apt)
            PKGS="nmap arp-scan iproute2 python3 python3-venv python3-yaml python3-flask python3-requests python3-defusedxml python3-scapy"
            INSTALL_CMD=(apt-get install -y) ;;
        dnf)
            PKGS="nmap arp-scan iproute python3 python3-pyyaml python3-flask python3-requests python3-defusedxml python3-scapy"
            INSTALL_CMD=(dnf install -y) ;;
        pacman)
            PKGS="nmap arp-scan iproute2 python python-pyyaml python-flask python-requests python-defusedxml python-scapy"
            INSTALL_CMD=(pacman -S --needed --noconfirm) ;;
        zypper)
            PKGS="nmap arp-scan iproute2 python3 python3-PyYAML python3-Flask python3-requests python3-defusedxml python3-scapy"
            INSTALL_CMD=(zypper --non-interactive install) ;;
        apk)
            PKGS="nmap arp-scan iproute2 python3 py3-yaml py3-flask py3-requests py3-defusedxml py3-scapy"
            INSTALL_CMD=(apk add) ;;
        *)
            PKGS=""
            INSTALL_CMD=() ;;
    esac
}

run_root() {
    if [[ $EUID -eq 0 ]]; then
        "$@"
    elif command -v sudo >/dev/null 2>&1; then
        sudo "$@"
    else
        echo "ERROR: se necesita root o sudo para: $*" >&2
        return 1
    fi
}

check_tools() {
    local missing=()
    local bin
    for bin in nmap arp-scan ip; do
        command -v "$bin" >/dev/null 2>&1 || missing+=("$bin")
    done
    if ((${#missing[@]})); then
        say "faltan" "${missing[*]}"
        if [[ -n "$PKGS" ]]; then
            echo "  instalar con : sudo ${INSTALL_CMD[*]} $PKGS"
            if ((INSTALL_DEPS)); then
                echo "  instalando dependencias de sistema..."
                # $PKGS son paquetes separados por espacios: se convierte en array
                # para pasarlos como argumentos sin depender de la expansión sin comillas.
                read -r -a PKGS_ARR <<< "$PKGS"
                if ! run_root "${INSTALL_CMD[@]}" "${PKGS_ARR[@]}"; then
                    echo "  aviso       : la instalación automática falló; instala nmap, arp-scan" >&2
                    echo "                e iproute2 a mano y usa --venv para las dependencias Python" >&2
                fi
            else
                echo "  (usa --install-deps para instalarlas automáticamente)"
            fi
        else
            echo "  instala nmap, arp-scan e iproute2 con el gestor de tu distribución"
        fi
    else
        say "herramientas" "nmap, arp-scan e iproute2 presentes"
    fi
}

check_python() {
    if ! "$1" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)'; then
        echo "ERROR: se requiere Python 3.11 o superior (detectado: $("$1" -V 2>&1))" >&2
        exit 1
    fi
}

# --------------------------------------------------------------------------- #
# Prefijo: ruta absoluta y saneada
# --------------------------------------------------------------------------- #
normalize_prefix() {
    if [[ -z "$PREFIX" ]]; then
        die "--prefix necesita un directorio"
    fi
    case "$PREFIX" in
        /*) ;;
        *) PREFIX="$ROOT/$PREFIX" ;;
    esac
    PREFIX="${PREFIX%/}"
    if [[ -z "$PREFIX" || "$PREFIX" == "/" ]]; then
        die "--prefix no puede ser la raíz del sistema"
    fi
}

# --------------------------------------------------------------------------- #
# Modo sistema
# --------------------------------------------------------------------------- #
do_system() {
    normalize_prefix
    echo "== Batrade · instalación de sistema =="
    if ((DRY_RUN)); then
        say "modo" "dry-run (no se modifica nada)"
    fi
    require_root --system --prefix "$PREFIX"

    local bin_dir="${BATRADE_BIN_DIR:-/usr/local/bin}"
    local venv="$PREFIX/.venv"
    local -a sync_args=("$ROOT" "$PREFIX")

    detect_distro
    say "distro" "$DISTRO"
    say "gestor" "${PM:-no detectado}"
    say "destino" "$PREFIX"
    say "comando" "$bin_dir/batrade"

    check_tools
    check_python "$PY"

    if [[ -d "$PREFIX" ]]; then
        say "destino" "ya existe; se actualiza conservando datos y configuración"
    fi
    run mkdir -p "$PREFIX"
    if ((DRY_RUN)); then
        sync_args+=(--dry-run)
    fi
    run bash "$ROOT/scripts/sync_tree.sh" "${sync_args[@]}"

    if [[ -x "$venv/bin/python" ]]; then
        say "venv" "existente ($venv)"
    else
        run "$PY" -m venv "$venv"
    fi
    run "$venv/bin/python" -m pip install --quiet --upgrade pip || true
    run "$venv/bin/python" -m pip install --quiet -e "$PREFIX"

    if [[ -f "$PREFIX/.env" ]]; then
        say ".env" "existente conservado (permisos sin cambios)"
    elif ((DRY_RUN)); then
        plan "crear $PREFIX/.env desde .env.example con permisos 600"
    else
        cp "$PREFIX/.env.example" "$PREFIX/.env"
        chmod 600 "$PREFIX/.env"
        say ".env" "creado (600)"
    fi
    if [[ -f "$PREFIX/config.yaml" ]]; then
        say "config.yaml" "existente conservado"
    fi

    run "$venv/bin/python" -m batrade --root "$PREFIX" init
    if ((DRY_RUN)); then
        plan "listar interfaces: $venv/bin/python -m batrade --root $PREFIX interfaces"
        plan "diagnóstico: $venv/bin/python -m batrade --root $PREFIX doctor"
    else
        "$venv/bin/python" -m batrade --root "$PREFIX" interfaces | sed 's/^/  /'
        "$venv/bin/python" -m batrade --root "$PREFIX" doctor | sed 's/^/  /'
    fi

    # Wrapper en vez de enlace: fija BATRADE_ROOT para que el comando funcione
    # desde cualquier directorio y aunque el paquete no sea editable.
    local wrapper="$bin_dir/batrade"
    if ((DRY_RUN)); then
        plan "escribir wrapper $wrapper -> $venv/bin/batrade (BATRADE_ROOT=$PREFIX)"
    else
        mkdir -p "$bin_dir"
        local tmp="$wrapper.tmp.$$"
        cat > "$tmp" <<WRAPPER
#!/bin/sh
# Generado por install.sh --system. No editar a mano.
export BATRADE_ROOT="\${BATRADE_ROOT:-$PREFIX}"
exec "$venv/bin/batrade" "\$@"
WRAPPER
        chmod 755 "$tmp"
        mv -f "$tmp" "$wrapper"
        say "comando" "$wrapper"
    fi

    case ":$PATH:" in
        *":$bin_dir:"*) ;;
        *)
            echo "  aviso       : $bin_dir no está en PATH; sudo suele usar secure_path" >&2
            echo "                (mira 'sudo -V | grep secure_path' o usa la ruta completa)" >&2
            ;;
    esac

    if ((START_AFTER)); then
        run "$venv/bin/python" -m batrade --root "$PREFIX" start
        say "arranque" "sensor y panel en segundo plano"
    fi

    if ((DRY_RUN)); then
        echo "  (dry-run) no se ha modificado nada"
    else
        echo
        echo "Listo. Prueba con:"
        echo "  batrade doctor           # o: sudo $venv/bin/python -m batrade --root $PREFIX doctor"
        echo "  sudo batrade start       # sensor + panel (root para modo live)"
        echo "  sudo batrade reset-db    # limpia pruebas y simulaciones"
    fi
}

# --------------------------------------------------------------------------- #
# Desinstalación
# --------------------------------------------------------------------------- #
do_uninstall() {
    normalize_prefix
    echo "== Batrade · desinstalación =="
    local bin_dir="${BATRADE_BIN_DIR:-/usr/local/bin}"
    local wrapper="$bin_dir/batrade"

    if ((DRY_RUN)); then
        say "modo" "dry-run (no se modifica nada)"
    else
        require_root --uninstall --prefix "$PREFIX"
    fi

    # No se quita el código con componentes vivos: mejor parar antes.
    local pidfile pid
    for pidfile in "$PREFIX/var/sensor.pid" "$PREFIX/var/dashboard.pid"; do
        if [[ -f "$pidfile" ]]; then
            pid="$(cat "$pidfile" 2>/dev/null || true)"
            if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
                die "hay un proceso vivo ($pidfile). Deténlo antes: batrade stop"
            fi
        fi
    done

    # La confirmación de --purge va antes de tocar nada: si se cancela, ni el
    # comando ni el código se han modificado.
    if ((PURGE)); then
        if ! confirm_word "Se borrarán TAMBIÉN var/, .env y config.yaml de $PREFIX. Escribe BORRAR:" BORRAR; then
            die "desinstalación cancelada"
        fi
    fi

    if [[ -e "$wrapper" || -L "$wrapper" ]]; then
        run rm -f "$wrapper"
        say "comando" "eliminado ($wrapper)"
    else
        say "comando" "no existe ($wrapper)"
    fi

    if [[ ! -d "$PREFIX" ]]; then
        say "destino" "no existe ($PREFIX)"
        return 0
    fi

    if ((PURGE)); then
        run rm -rf "$PREFIX"
        say "destino" "eliminado por completo ($PREFIX)"
        return 0
    fi

    local entry base
    for entry in "$PREFIX"/* "$PREFIX"/.[!.]*; do
        [[ -e "$entry" || -L "$entry" ]] || continue
        base="$(basename "$entry")"
        case "$base" in
            var|.env|config.yaml)
                say "conservado" "$base"
                continue
                ;;
        esac
        run rm -rf "$entry"
    done
    say "destino" "código eliminado; datos y configuración conservados en $PREFIX"
}

if ((UNINSTALL)); then
    do_uninstall
    exit 0
fi
if ((SYSTEM)); then
    do_system
    exit 0
fi

# --------------------------------------------------------------------------- #
# Modo repositorio (desarrollo): comportamiento histórico
# --------------------------------------------------------------------------- #
echo "== Batrade · instalación =="
cd "$ROOT"

detect_distro
say "distro" "$DISTRO"
say "gestor" "${PM:-no detectado}"

check_tools

check_python "$PY"
PY_BIN="$(command -v "$PY")"
say "python" "$("$PY" -V)"

if ((USE_VENV)); then
    if [[ ! -x "$ROOT/.venv/bin/python" ]]; then
        if ! "$PY" -m venv "$ROOT/.venv"; then
            echo "ERROR: no se pudo crear el venv; instala python3-venv (apt) o python3 (dnf)" >&2
            exit 3
        fi
    fi
    PY_BIN="$ROOT/.venv/bin/python"
    "$PY_BIN" -m pip install --quiet --upgrade pip >/dev/null 2>&1 || true
    if ! "$PY_BIN" -m pip install --quiet -e "$ROOT"; then
        echo "ERROR: pip no pudo instalar las dependencias del proyecto" >&2
        exit 3
    fi
    say "venv" "$ROOT/.venv"
fi

if ! "$PY_BIN" - <<'PYEOF'
import importlib.util
import sys

need = {"yaml": "PyYAML", "flask": "Flask", "requests": "requests",
        "defusedxml": "defusedxml", "scapy": "scapy"}
missing = [pkg for mod, pkg in need.items()
           if importlib.util.find_spec(mod) is None]
if missing:
    print("  faltan módulos Python:", ", ".join(missing))
    sys.exit(3)
PYEOF
then
    echo "  sugerencia  : bash install.sh --venv   (todo en .venv, sin tocar el sistema)"
    exit 3
fi
say "módulos" "completos"

mkdir -p var/scans var/log
chmod 700 var/scans 2>/dev/null || true
if [[ ! -f .env ]]; then
    cp .env.example .env
    chmod 600 .env
    say ".env" "creado desde .env.example (permisos 600)"
else
    chmod 600 .env
    say ".env" "existente"
fi

"$PY_BIN" -m batrade init
"$PY_BIN" -m batrade interfaces | sed 's/^/  /'
"$PY_BIN" -m batrade doctor | sed 's/^/  /'

# --------------------------------------------------------------------------- #
# Unidades systemd (opcionales, modo repositorio)
# --------------------------------------------------------------------------- #
if ((INSTALL_SYSTEMD)); then
    if [[ $EUID -ne 0 ]]; then
        echo "  systemd     : se necesita root para instalar las unidades" >&2
        exit 1
    fi
    if [[ "$ROOT" == /home/* ]]; then
        echo "  aviso       : el repositorio está bajo /home y las unidades usan" >&2
        echo "                ProtectHome=true, así que systemd NO podrá leer $ROOT" >&2
        echo "                y el servicio fallará al arrancar." >&2
        echo "                Opciones: usar 'install.sh --system' (instala en /opt)" >&2
        echo "                o no usar systemd: '$PY_BIN -m batrade start' y 'stop'." >&2
    fi
    # Usuario de servicio sin shell (Debian/Kali, Fedora/RHEL, Arch, openSUSE).
    if ! id -u batrade >/dev/null 2>&1; then
        if command -v useradd >/dev/null 2>&1; then
            useradd -r -s /usr/sbin/nologin batrade
            say "usuario" "batrade creado (sin shell)"
        else
            echo "  aviso       : crea un usuario 'batrade' sin shell para el servicio" >&2
        fi
    fi
    chown -R batrade:batrade "$ROOT/var" 2>/dev/null || true
    sed -e "s|/opt/batrade|$ROOT|g" \
        -e "s|^ExecStart=.*batrade sensor.*|ExecStart=$PY_BIN -m batrade sensor --mode auto|" \
        deploy/batrade-sensor.service > /etc/systemd/system/batrade-sensor.service
    sed -e "s|/opt/batrade|$ROOT|g" \
        -e "s|^ExecStart=.*batrade dashboard.*|ExecStart=$PY_BIN -m batrade dashboard --host 127.0.0.1 --port 8000|" \
        deploy/batrade-dashboard.service > /etc/systemd/system/batrade-dashboard.service
    chmod 644 /etc/systemd/system/batrade-*.service
    systemctl daemon-reload
    say "systemd" "unidades instaladas (no habilitadas)"
    echo "                systemctl enable --now batrade-sensor batrade-dashboard"
else
    say "systemd" "omitido (usa --systemd para instalar las unidades)"
fi

# --------------------------------------------------------------------------- #
# Comando `batrade` en el PATH (opcional, modo repositorio)
# --------------------------------------------------------------------------- #
if ((LINK_BIN)); then
    SCRIPT="$ROOT/.venv/bin/batrade"
    if [[ ! -x "$SCRIPT" ]]; then
        echo "  enlace      : no existe .venv/bin/batrade; ejecuta --venv primero" >&2
    else
        if [[ $EUID -eq 0 ]]; then
            BIN_DIR="${BATRADE_BIN_DIR:-/usr/local/bin}"
        else
            BIN_DIR="${BATRADE_BIN_DIR:-$HOME/.local/bin}"
        fi
        mkdir -p "$BIN_DIR"
        ln -sfn "$SCRIPT" "$BIN_DIR/batrade"
        say "enlace" "$BIN_DIR/batrade -> $SCRIPT"
        case ":$PATH:" in
            *":$BIN_DIR:"*) ;;
            *) echo "  aviso       : añade $BIN_DIR al PATH para usar 'batrade'" >&2 ;;
        esac
    fi
fi

echo
echo "Listo. Siguiente paso:"
echo "  $PY_BIN -m batrade demo && $PY_BIN -m batrade dashboard   # ver el panel"
echo "  $PY_BIN -m batrade sensor --mode degraded                # arrancar el sensor"
echo "  $PY_BIN -m batrade interfaces                            # Ethernet/Wi-Fi detectadas"
echo
echo "Para una instalación de sistema (raíz, comando en el PATH):"
echo "  sudo bash install.sh --system --install-deps --start"
