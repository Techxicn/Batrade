"""Ejecución de herramientas externas con un entorno mínimo (S-03).

Los subprocesos no heredan el entorno del sensor: ni tokens de Telegram, ni
webhooks de Discord, ni variables del operador. Sólo lo imprescindible para que
`nmap`, `arp-scan` e `ip` encuentren sus rutas y hablen en C.
"""
from __future__ import annotations

import os

PATH_POR_DEFECTO = ("/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:"
                    "/sbin:/bin")


def env_minimo() -> dict[str, str]:
    """Entorno para `subprocess.run`: PATH, LC_ALL y LANG, nada más."""
    return {
        "PATH": os.environ.get("PATH") or PATH_POR_DEFECTO,
        "LC_ALL": "C",
        "LANG": "C",
    }
