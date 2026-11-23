"""probe_cidr: cierre garantizado y sin el límite de select() (F-04)."""
from __future__ import annotations

import selectors
from types import SimpleNamespace

import pytest

from batrade.net import neigh


class _SocketFalso:
    def __init__(self) -> None:
        self.cerrado = False
        self.error = 0

    def setblocking(self, _valor: bool) -> None:
        pass

    def connect(self, _destino) -> None:
        raise BlockingIOError

    def fileno(self) -> int:
        return 1

    def getsockopt(self, _nivel, _opcion) -> int:
        return self.error

    def close(self) -> None:
        self.cerrado = True


class _SelectorQueFalla:
    def __init__(self) -> None:
        self.registrados: list = []

    def register(self, fileobj, events, data=None) -> None:
        self.registrados.append(fileobj)

    def select(self, timeout=None):
        raise ValueError("too many file descriptors in select()")

    def unregister(self, fileobj) -> None:
        pass

    def close(self) -> None:
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_exc) -> None:
        self.close()


class _SelectorTodoEscritura:
    def __init__(self) -> None:
        self.claves: list = []

    def register(self, fileobj, events, data=None) -> None:
        self.claves.append(SimpleNamespace(fileobj=fileobj))

    def select(self, timeout=None):
        return [(clave, selectors.EVENT_WRITE) for clave in self.claves]

    def unregister(self, fileobj) -> None:
        pass

    def close(self) -> None:
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_exc) -> None:
        self.close()


@pytest.fixture
def sockets_falsos(monkeypatch):
    fabricados: list[_SocketFalso] = []

    def fabrica(*_args, **_kwargs):
        sock = _SocketFalso()
        fabricados.append(sock)
        return sock

    monkeypatch.setattr(neigh.socket, "socket", fabrica)
    return fabricados


def test_si_el_selector_falla_no_se_filtran_sockets(monkeypatch, sockets_falsos):
    monkeypatch.setattr(neigh.selectors, "DefaultSelector", _SelectorQueFalla)

    assert neigh.probe_cidr("10.0.0.0/28", concurrency=4) == 0

    assert sockets_falsos, "no se creó ningún socket: la prueba no sirve"
    assert all(sock.cerrado for sock in sockets_falsos)


def test_un_lote_mayor_que_fd_setsize_no_revienta(monkeypatch, sockets_falsos):
    """Más de 1024 descriptores en un lote: con select() esto lanzaba ValueError."""
    monkeypatch.setattr(neigh.selectors, "DefaultSelector", _SelectorTodoEscritura)

    conectados = neigh.probe_cidr("10.0.0.0/21", concurrency=3000)

    assert len(sockets_falsos) == 2046          # hosts de un /21
    assert len(sockets_falsos) > 1024
    assert conectados == 2046
    assert all(sock.cerrado for sock in sockets_falsos)


def test_los_sockets_con_error_esperado_tambien_cuentan(monkeypatch, sockets_falsos):
    import errno

    monkeypatch.setattr(neigh.selectors, "DefaultSelector", _SelectorTodoEscritura)

    def fabrica(*_args, **_kwargs):
        sock = _SocketFalso()
        sock.error = errno.ECONNREFUSED
        sockets_falsos.append(sock)
        return sock

    monkeypatch.setattr(neigh.socket, "socket", fabrica)
    assert neigh.probe_cidr("10.0.0.0/30", concurrency=8) == 2
