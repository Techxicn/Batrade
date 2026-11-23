"""Puntuación de flujos: interfaz abstracta y centinela.

La interfaz existe para que el motor no sepa qué implementación tiene delante.
En esta iteración solo hay ``DummyScorer``; el modelo real (scikit-learn, extra
``[ml]``) se enchufa detrás sin tocar el motor.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Sequence

from batrade.flow.flow import Flow


class Scorer(ABC):
    """Contrato mínimo: aprender de lo normal y puntuar lo desconocido."""

    @abstractmethod
    def fit(self, flows_normales: Sequence[Flow]) -> None:
        """Ajusta el modelo con flujos normales (sin supervisión)."""

    @abstractmethod
    def score(self, flow: Flow) -> float:
        """Devuelve una puntuación; mayor significa más anómalo."""


class DummyScorer(Scorer):
    """Fallback: no aprende nada y puntúa siempre 0.0.

    Con él el motor arranca y ejerce el camino completo (cola, colector,
    características), pero nunca supera el umbral y no emite hallazgos.
    """

    def fit(self, flows_normales: Sequence[Flow]) -> None:
        return None

    def score(self, flow: Flow) -> float:
        return 0.0
