# Decisiones de arquitectura

Registro de las decisiones tomadas para Batrade. Cada una se anota con su justificación en
una línea. No se reescriben: si una decisión cambia, se añade una nueva entrada que la
sustituye y se deja la anterior con la fecha del cambio.

---

## D-01 · El motor de reglas se mantiene; el análisis por flujo es un módulo nuevo

**Decisión.** El motor de reglas actual (`batrade/detect/`) se conserva tal cual. La
detección de anomalías por flujo se añade como módulo nuevo en `batrade/flow/` y se integra
como una regla más del `Engine`.

**Por qué.** Las reglas por paquete ya están probadas, explicadas y entran en los eventos
tal cual; el flujo aporta contexto sin obligar a rehacer la detección ni a cambiar el
formato de lo que ve el operador.

---

## D-02 · Interfaz de captura separada de la de gestión

**Decisión.** Se añade `network.capture_interface`, opcional y por defecto igual a
`network.interface`, para poder capturar en un puerto espejo sin mover el tráfico de
gestión del sensor.

**Por qué.** Un sensor en un puerto espejo no debe depender de la interfaz por la que se
administra, y las instalaciones actuales siguen funcionando sin tocar la configuración.

---

## D-03 · Acceso remoto al panel por túnel SSH

**Decisión.** El método oficial para llegar al dashboard desde otra máquina es el túnel SSH
(`ssh -L 8000:127.0.0.1:8000 ...`). Un reverse proxy con TLS queda como opción documentada;
el Flask nunca se expone directamente.

**Por qué.** El túnel da transporte cifrado y autenticación sin mantener un servidor web, y
conserva `localhost` como origen, que es lo que necesitan las notificaciones del navegador.

---

## D-04 · Multi-VLAN con instancias separadas

**Decisión.** El soporte multi-VLAN se resuelve con varias instancias del sensor, cada una
con su propio `--prefix` (raíz de datos, base y logs), no con varias interfaces en un solo
sensor.

**Por qué.** Cada VLAN queda aislada en su base e historial, un fallo o un reinicio no afecta
a las demás y no hay que repartir observaciones entre redes dentro del mismo proceso.

---

## D-05 · La licencia se decide antes de cualquier release público

**Decisión.** La licencia se elige antes del primer release público; hasta entonces el
repositorio no se considera open source y no se anuncia como tal.

**Por qué.** Publicar sin licencia deja el código sin permisos de uso ni de contribución, y
cambiar de licencia después de que terceros hayan contribuido es mucho más caro.

---

## D-06 · El aviso de captura == gestión solo se muestra si la clave es explícita

**Decisión.** `doctor` avisa de que `capture_interface` y `interface` son iguales
solo cuando `capture_interface` se ha fijado explícitamente en el YAML
(`Config.capture_explicit`). Con el default `null` no se avisa.

**Por qué.** En una instalación normal ambas resuelven al mismo valor por
construcción; avisar siempre enseñaría al operador a ignorar los avisos.

---

## D-07 · Iteración 2 del motor de flujos: Isolation Forest principal, K-Means como segmentador

**Decisión.** En la iteración 2 del motor de flujos (`batrade/flow/`) se implementa
Isolation Forest como scorer principal, con `numpy` como dependencia opcional `[ml]`.
K-Means se usa como segmentador del tráfico normal (elige `k` una vez sobre la línea
base y se versiona con el modelo), no como scorer independiente. El autoencoder queda
pospuesto a una fase posterior, con decisión explícita sobre la dependencia.

**Por qué.** K-Means como scorer exige elegir `k`, que envejece mal y produce falsos
positivos o ceguera según el valor; como segmentador, `k` se fija una vez y no se toca
en producción. Isolation Forest no necesita `k`, es explicable (profundidad de
aislamiento) y responde al PDF.

---

## D-08 · Formato del modelo serializado

**Decisión.** El modelo entrenado se guarda como `var/flow_model.npz` (`numpy.savez`)
más `var/flow_model.json` con metadatos (versión del formato, `k` si aplica, umbral,
fecha de entrenamiento, hash del pcap de entrenamiento, versión de Batrade). No se
usa `pickle` ni `joblib`.

**Por qué.** `numpy.savez` es reproducible, auditable y no añade dependencias; el JSON
de metadatos permite saber con qué datos y con qué versión se entrenó el modelo sin
abrir el binario. `pickle` es un riesgo de seguridad si alguien manipula el archivo.

---

## D-09 · El motor de flujos complementa a las reglas, no las duplica

**Decisión.** El motor de flujos (`batrade/flow/`) no implementa detección de escaneos
de puertos ni de barridos de hosts: eso lo siguen haciendo `SynScanRule` y
`ArpSweepRule` sobre las observaciones. El motor de flujos se centra en lo que las
reglas no ven: balizamiento C2 con jitter, exfiltración con bytes anómalos, conexiones
a puertos inusuales y flujos individuales que se desvían de la línea base. Las features
agregadas por origen (puertos distintos por IP origen en una ventana) quedan fuera de
esta fase.

**Por qué.** Un escaneo de 120 puertos produce 120 flujos de 1 paquete cada uno, y
ninguno es anómalo por sí solo; duplicar la detección en el motor de flujos añadiría
falsos positivos y deuda. La señal de barrido vive en el agregado por origen, que es
otro módulo, no el scorer por flujo.

---

## D-10 · La detección de balizamiento C2 por periodo largo requiere features
agregadas por origen y una línea base real

**Decisión.** El scorer por flujo (Isolation Forest sobre features por flujo)
detecta anomalías globalmente raras (exfiltración, flujos con forma imposible),
pero no una baliza C2 de periodo largo con jitter regular: con 10 features por
flujo y split aleatorio, una anomalía en una sola dimensión se diluye. Medido:
la baliza sintética de 12 paquetes cada 60 s queda en el percentil ~97 de la
línea base, score 0.9826, por debajo del flujo más aislado del entrenamiento.

La Fase 3.5 (features agregadas por origen: puertos/destinos distintos,
regularidad entre conexiones) queda documentada como trabajo futuro y NO se
abre hasta que exista una línea base real con >= 300 flujos y score máximo
<= 0.90. Sin esa condición, las features agregadas repetirían el problema de
`segmentado` (percentil con resolución de ~4 % por flujo, score aplanado) y
producirían un motor que pasa tests y no detecta C2 en producción.

**Por qué.** Documentar la condición de datos evita que alguien abra la Fase
3.5 con 60 flujos sintéticos y concluya que "el motor no funciona" cuando en
realidad le faltan datos, no código.

---

## D-11 · Cierre de la Fase 3: IF global en producción, K-Means etiquetador,
segmentado experimental

**Decisión.** El motor de flujos queda cerrado con IsolationForestScorer global
como scorer de producción (modos `none` o `kmeans`, que puntúan igual).
KMeansSegmenter se usa como etiquetador opcional (añade detalle["segmento"] a
los hallazgos) pero no altera el score. SegmentadoScorer queda como
experimental: empeora la separación con la línea base sintética de 60 flujos
(C2 0.9826 -> 0.9538, normal 0.42 -> 0.83) porque un segmento de 14-26 flujos
tiene resolución de ~4 % por flujo. No se activa en producción hasta reentrenar
con cientos o miles de flujos por segmento.

**Por qué.** Documentarlo evita que alguien active `segmentado` esperando que
mejore la detección y concluya que el motor no funciona.

---

## D-12 · La licencia sigue sin concederse: repositorio propietario hasta que el
titular decida

**Decisión.** El repositorio no incluye `LICENSE`, no declara licencia en
`pyproject.toml` y no se distribuye públicamente: queda «todos los derechos
reservados» (propietario). No es un olvido ni una decisión de un tercero: es el
estado formal hasta que el titular elija licencia. Criterios ya fijados para
cuando la elija:

- Las dependencias permiten licencia permisiva o copyleft propia: PyYAML (MIT),
  Flask (BSD-3-Clause), requests (Apache-2.0), defusedxml (PSFL), numpy
  (BSD-3-Clause) y **scapy (GPL-2.0-only)**. Como dependencia externa no obliga a
  licenciar Batrade bajo GPL, pero impide relicenciar código copiado de scapy y
  obliga a no vendorizarlo dentro del árbol.
- Mientras no haya licencia **no se aceptan contribuciones de código de
  terceros**: un parche aceptado sin licencia crea cotitularidad y bloquea la
  elección posterior. Lo que llegue se trata como sugerencia (CONTRIBUTING.md).
- Para cerrar D-12 antes de cualquier release público: añadir `LICENSE`,
  declarar la licencia en `pyproject.toml` (PEP 639), actualizar README y
  revisar que ninguna fixture venga de terceros con licencia incompatible (los
  pcaps son sintéticos, generados por `scripts/make_fixtures.py`).
- Sin `LICENSE` no hay release público, ni binarios, ni imágenes.

**Por qué.** D-05 dejaba la licencia como condición previa a un release; esta
fase cierra ese punto fijando el estado actual (propietario) y los requisitos de
salida, para que nadie asuma que el proyecto es open source por estar accesible o
porque una dependencia suya sea MIT.

---

## D-13 · Licencia MIT adoptada y aceptación de contribuciones

**Decisión.** El proyecto se publica bajo MIT (ver LICENSE). Se aceptan
contribuciones bajo los mismos términos. `scapy` sigue siendo GPL-2.0-only como
dependencia externa, no afecta a la licencia del proyecto. Esta decisión
sustituye a D-12, que quedó obsoleta tras el PR #6.

**Por qué.** Un repositorio sin licencia no se puede usar ni contribuir
legalmente; la release v0.1.0 ya se publicó bajo MIT.
