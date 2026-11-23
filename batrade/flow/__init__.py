"""Flujos de red: agrupación, características y motor de anomalías.

Módulo separado del motor de reglas (``batrade/detect``): una regla mira un
paquete, un flujo mira una conversación. En esta iteración sólo hay esqueleto:
el colector agrupa, se extraen características y se puntúa con ``DummyScorer``,
que nunca supera el umbral.
"""
from __future__ import annotations

from batrade.flow.collector import FlowCollector
from batrade.flow.engine import FlowEngine
from batrade.flow.features import FlowFeatures, extract
from batrade.flow.flow import Flow
from batrade.flow.scorer import DummyScorer, IsolationForestScorer, Scorer

__all__ = ["Flow", "FlowCollector", "FlowFeatures", "Scorer", "DummyScorer",
           "IsolationForestScorer", "FlowEngine", "extract"]
