/* Panel en vivo de Batrade: sondea /api/live sin recargar la página.
 *
 * Reglas que este archivo respeta siempre:
 *  - sólo hace GET a la única ruta JSON del panel: nada de escrituras;
 *  - ningún dato de la red pasa por innerHTML: todo texto entra por
 *    textContent y los atributos por setAttribute;
 *  - sin dependencias, CDN ni frameworks: funciona con el panel sin internet.
 */
(function () {
  "use strict";

  var cuerpo = document.body;
  if (!cuerpo || !cuerpo.dataset || !cuerpo.dataset.liveUrl) return;

  // dashboard.live_poll_s llega como atributo data-; se acota por si el HTML
  // fuera viejo o manipulado.
  var POLL_MS = limitar(parseInt(cuerpo.dataset.livePoll, 10) || 3, 1, 60) * 1000;
  var OCULTA_MS = 15000;      // pestaña oculta: se baja el ritmo
  var MAX_ESPERA_MS = 30000;  // techo del retroceso exponencial
  var TOPE_EVENTOS = 50;      // store.LIVE_MAX_EVENTS

  // Avisos dentro de la página
  var MAX_AVISOS = 4;         // máximo de pop-ups visibles a la vez
  var AVISO_WARN_MS = 10000;  // un warn desaparece solo; un crit espera al cierre
  var RAFAGA_MAX = 3;         // más de 3 en un ciclo => un único aviso agrupado
  var ETIQUETA_SEV = { crit: "Crítico", warn: "Advertencia", info: "Informativo" };

  // Sonido sintetizado (Web Audio, sin archivos) y preferencias
  var CLAVE_PREFS = "batrade.live.prefs";
  var SONIDO_MIN_MS = 5000;   // como mucho un sonido cada 5 s

  var estado = {
    cursor: null,             // id del último evento warn/crit entregado
    vistos: Object.create(null),
    temporizador: null,
    espera: POLL_MS,
    detenido: false,
    activado: false,          // interruptor "Avisos": silencio hasta el clic
    prefs: { sonido: true, notificaciones: true, soloCriticas: false },
    audio: null,
    ultimoSonido: 0,
    noVistas: 0,              // alertas sin ver, para el título "(N) Batrade"
    tituloOriginal: document.title
  };

  function limitar(valor, minimo, maximo) {
    return Math.min(maximo, Math.max(minimo, valor));
  }

  function sinConexion(visible, texto) {
    var aviso = document.getElementById("live-offline");
    if (!aviso) return;
    if (texto) aviso.textContent = texto;
    aviso.hidden = !visible;
  }

  function intervalo() {
    return document.hidden ? Math.max(OCULTA_MS, POLL_MS) : POLL_MS;
  }

  function programar(ms) {
    window.clearTimeout(estado.temporizador);
    if (estado.detenido) return;
    estado.temporizador = window.setTimeout(sondear, ms);
  }

  function url() {
    var base = cuerpo.dataset.liveUrl;
    if (estado.cursor === null) return base;
    return base + (base.indexOf("?") === -1 ? "?" : "&") +
      "after=" + encodeURIComponent(String(estado.cursor));
  }

  function sondear() {
    fetch(url(), {
      method: "GET",
      credentials: "same-origin",
      cache: "no-store",
      headers: { "Accept": "application/json" }
    }).then(function (respuesta) {
      // Con token configurado, una sesión vencida devuelve 401 (o redirige al
      // login): se detiene el sondeo en vez de martillear el servidor.
      if (respuesta.status === 401 || respuesta.redirected) {
        estado.detenido = true;
        throw new Error("sesión");
      }
      if (!respuesta.ok) throw new Error("HTTP " + respuesta.status);
      return respuesta.json();
    }).then(function (datos) {
      estado.espera = intervalo();
      sinConexion(false);
      alRecibir(datos);
      programar(estado.espera);
    }).catch(function (error) {
      if (estado.detenido) {
        sinConexion(true, "Sin conexión con el panel: la sesión no es válida. " +
          "Recarga la página e inicia sesión.");
        return;
      }
      estado.espera = Math.min(MAX_ESPERA_MS,
        Math.max(estado.espera, POLL_MS) * 2);
      sinConexion(true, "Sin conexión con el panel");
      programar(estado.espera);
    });
  }

  function alRecibir(datos) {
    if (!datos || typeof datos !== "object") return;
    var maxId = Number(datos.max_id) || 0;
    var eventos = Array.isArray(datos.eventos) ? datos.eventos : [];
    var primera = estado.cursor === null;

    // Al abrir o recargar, el cursor arranca en max_id: lo que ya estaba en la
    // base no genera avisos.
    if (primera) estado.cursor = maxId;

    var nuevos = [];
    for (var i = 0; i < eventos.length; i++) {
      var ev = eventos[i];
      if (!ev || typeof ev.id !== "number") continue;
      if (estado.vistos[ev.id]) continue;
      estado.vistos[ev.id] = true;
      nuevos.push(ev);
    }
    for (var j = 0; j < nuevos.length; j++) {
      if (nuevos[j].id > estado.cursor) estado.cursor = nuevos[j].id;
    }
    // Si la respuesta vino llena puede haber más eventos esperando: el cursor
    // se queda en el último entregado para no saltarse ninguno.
    if (eventos.length < TOPE_EVENTOS) {
      estado.cursor = Math.max(estado.cursor, maxId);
    }
    if (primera) return;
    if (!nuevos.length) return;

    presentar(nuevos);
  }

  function presentar(eventos) {
    var destino = cuerpo.dataset.eventsUrl || "/events";
    var visibles = [];
    var peor = "warn";
    for (var i = 0; i < eventos.length; i++) {
      if (estado.prefs.soloCriticas && eventos[i].severidad !== "crit") continue;
      visibles.push(eventos[i]);
      if (eventos[i].severidad === "crit") peor = "crit";
    }
    if (!visibles.length) return;

    // Un solo sonido por ciclo, con la severidad más alta del lote.
    sonar(peor);

    var agrupado = visibles.length > RAFAGA_MAX;
    // Una ráfaga no puede tapar el panel: un solo aviso con el recuento.
    if (agrupado) {
      aviso(peor, visibles.length + " alertas nuevas",
        "Se agruparon para no tapar el panel.", destino);
    } else {
      for (var j = 0; j < visibles.length; j++) {
        var ev = visibles[j];
        aviso(ev.severidad, ev.tipo || "Alerta", ev.resumen || null, destino);
      }
    }

    // Fuera de la pestaña: se cuenta para el título y se intenta notificar.
    if (!document.hidden) return;
    contarNoVistas(visibles.length);
    if (agrupado) {
      notificar(peor, visibles.length + " alertas nuevas",
        "Se agruparon para no tapar el panel.", destino, "rafaga");
      return;
    }
    for (var k = 0; k < visibles.length; k++) {
      notificar(visibles[k].severidad, visibles[k].tipo || "Alerta",
        visibles[k].resumen || null, destino, visibles[k].id);
    }
  }

  function aviso(severidad, titulo, texto, enlace) {
    var caja = document.getElementById("live-alerts");
    if (!caja) return;
    var critico = severidad === "crit";
    // El más viejo se descarta al llegar al tope; los nuevos entran arriba.
    while (caja.children.length >= MAX_AVISOS) {
      caja.removeChild(caja.lastElementChild);
    }

    var el = document.createElement("div");
    el.className = "live-alert " + (critico ? "crit" : "warn");

    var cabecera = document.createElement("div");
    cabecera.className = "live-alert-head";
    var chip = document.createElement("span");
    chip.className = "chip " + (critico ? "crit" : "warn");
    chip.textContent = ETIQUETA_SEV[severidad] || ETIQUETA_SEV.warn;
    var cerrar = document.createElement("button");
    cerrar.type = "button";
    cerrar.className = "live-alert-close";
    cerrar.setAttribute("aria-label", "Cerrar aviso");
    cerrar.textContent = "×";
    cerrar.addEventListener("click", function () {
      if (el.parentNode) el.parentNode.removeChild(el);
    });
    cabecera.appendChild(chip);
    cabecera.appendChild(cerrar);

    var tituloEl = document.createElement("p");
    tituloEl.className = "live-alert-title";
    tituloEl.textContent = String(titulo || "Alerta");

    el.appendChild(cabecera);
    el.appendChild(tituloEl);
    if (texto) {
      var parrafo = document.createElement("p");
      parrafo.className = "live-alert-text";
      parrafo.textContent = String(texto);
      el.appendChild(parrafo);
    }
    if (enlace) {
      var ir = document.createElement("a");
      ir.setAttribute("href", enlace);
      ir.textContent = "Ver alertas →";
      el.appendChild(ir);
    }

    caja.insertBefore(el, caja.firstElementChild);
    // Los crit se quedan hasta que el usuario los cierre.
    if (!critico) {
      window.setTimeout(function () {
        if (el.parentNode) el.parentNode.removeChild(el);
      }, AVISO_WARN_MS);
    }
  }

  // --------------------------------------------------------------- sonido
  // Web Audio sintetizado: sin archivos ni red. El AudioContext sólo se crea
  // tras un gesto del usuario (política de autoplay de los navegadores).
  function contextoAudio() {
    if (!estado.activado || !estado.prefs.sonido) return null;
    var Constructor = window.AudioContext || window.webkitAudioContext;
    if (!Constructor) return null;
    if (!estado.audio) {
      try {
        estado.audio = new Constructor();
      } catch (error) {
        estado.audio = null;
        return null;
      }
    }
    if (estado.audio.state === "suspended") {
      var reanudar = estado.audio.resume();
      if (reanudar && typeof reanudar.catch === "function") {
        reanudar.catch(function () {});
      }
    }
    return estado.audio;
  }

  function tono(ctx, frecuencia, inicio, duracion, volumen) {
    var osc = ctx.createOscillator();
    var ganancia = ctx.createGain();
    osc.type = "sine";
    osc.frequency.setValueAtTime(frecuencia, inicio);
    ganancia.gain.setValueAtTime(0.0001, inicio);
    ganancia.gain.exponentialRampToValueAtTime(volumen, inicio + 0.02);
    ganancia.gain.exponentialRampToValueAtTime(0.0001, inicio + duracion);
    osc.connect(ganancia);
    ganancia.connect(ctx.destination);
    osc.start(inicio);
    osc.stop(inicio + duracion + 0.02);
  }

  function sonar(severidad) {
    if (!estado.activado || !estado.prefs.sonido) return;
    var ahora = Date.now();
    if (ahora - estado.ultimoSonido < SONIDO_MIN_MS) return;
    var ctx = contextoAudio();
    if (!ctx) return;
    estado.ultimoSonido = ahora;
    var t = ctx.currentTime + 0.02;
    if (severidad === "crit") {
      // Doble tono más grave: inconfundible frente a una advertencia.
      tono(ctx, 440, t, 0.18, 0.09);
      tono(ctx, 311, t + 0.26, 0.26, 0.09);
    } else {
      tono(ctx, 880, t, 0.16, 0.07);
    }
  }

  // ----------------------------------------------------------- preferencias
  function cargarPrefs() {
    try {
      var crudo = window.localStorage.getItem(CLAVE_PREFS);
      if (!crudo) return;
      var datos = JSON.parse(crudo);
      if (!datos || typeof datos !== "object") return;
      if (typeof datos.activado === "boolean") estado.activado = datos.activado;
      if (typeof datos.sonido === "boolean") estado.prefs.sonido = datos.sonido;
      if (typeof datos.notificaciones === "boolean") {
        estado.prefs.notificaciones = datos.notificaciones;
      }
      if (typeof datos.soloCriticas === "boolean") {
        estado.prefs.soloCriticas = datos.soloCriticas;
      }
    } catch (error) {
      // Modo privado, almacenamiento lleno o JSON corrupto: valores por defecto.
    }
  }

  function guardarPrefs() {
    try {
      window.localStorage.setItem(CLAVE_PREFS, JSON.stringify({
        activado: estado.activado,
        sonido: estado.prefs.sonido,
        notificaciones: estado.prefs.notificaciones,
        soloCriticas: estado.prefs.soloCriticas
      }));
    } catch (error) {
      // Sin almacenamiento la sesión funciona igual; sólo no se recuerda.
    }
  }

  function pintarInterruptor() {
    var boton = document.getElementById("live-toggle");
    if (!boton) return;
    boton.setAttribute("aria-pressed", estado.activado ? "true" : "false");
    boton.textContent = estado.activado ? "Avisos: on" : "Avisos: off";
    boton.classList.toggle("on", estado.activado);
  }

  function pedirPermisoNotificaciones() {
    if (!estado.prefs.notificaciones) return;
    if (typeof window.Notification === "undefined") return;
    if (window.Notification.permission !== "default") return;
    try {
      var peticion = window.Notification.requestPermission();
      if (peticion && typeof peticion.then === "function") {
        peticion.then(pintarNota, pintarNota);
      }
    } catch (error) {
      // Navegadores con callback: el permiso queda como estaba.
    }
  }

  function activar(activarAvisos) {
    estado.activado = activarAvisos;
    guardarPrefs();
    pintarInterruptor();
    if (activarAvisos) {
      // Este clic es el gesto que permite crear el AudioContext.
      contextoAudio();
      pedirPermisoNotificaciones();
    }
    pintarNota();
  }

  function conectarControles() {
    var boton = document.getElementById("live-toggle");
    if (boton) {
      boton.addEventListener("click", function () {
        activar(!estado.activado);
      });
    }
    var sonido = document.getElementById("live-pref-sound");
    if (sonido) {
      sonido.checked = estado.prefs.sonido;
      sonido.addEventListener("change", function () {
        estado.prefs.sonido = sonido.checked;
        guardarPrefs();
        if (sonido.checked) contextoAudio();
      });
    }
    var notificaciones = document.getElementById("live-pref-notify");
    if (notificaciones) {
      notificaciones.checked = estado.prefs.notificaciones;
      notificaciones.addEventListener("change", function () {
        estado.prefs.notificaciones = notificaciones.checked;
        guardarPrefs();
        if (notificaciones.checked && estado.activado) pedirPermisoNotificaciones();
        pintarNota();
      });
    }
    var criticas = document.getElementById("live-pref-crit");
    if (criticas) {
      criticas.checked = estado.prefs.soloCriticas;
      criticas.addEventListener("change", function () {
        estado.prefs.soloCriticas = criticas.checked;
        guardarPrefs();
      });
    }
  }

  // --------------------------------------- notificaciones del navegador y título
  // Sólo se usan con contexto seguro y permiso concedido. Si no, el aviso se
  // queda en el pop-up de la página y la barra explica por qué.
  function motivoSinNotificaciones() {
    if (typeof window.Notification === "undefined") {
      return "Este navegador no admite notificaciones; el aviso queda en la página.";
    }
    if (window.isSecureContext !== true) {
      return "Notificaciones no disponibles por HTTP con una IP: usa localhost " +
        "o HTTPS. El aviso queda en la página.";
    }
    if (window.Notification.permission === "denied") {
      return "Notificaciones bloqueadas en el navegador; el aviso queda en la página.";
    }
    if (window.Notification.permission === "default") {
      return "Notificaciones sin permiso todavía; el aviso queda en la página.";
    }
    return "";
  }

  function pintarNota() {
    var nota = document.getElementById("live-note");
    if (!nota) return;
    var motivo = (estado.activado && estado.prefs.notificaciones)
      ? motivoSinNotificaciones() : "";
    if (!motivo) {
      nota.textContent = "";
      nota.hidden = true;
      return;
    }
    nota.textContent = motivo;
    nota.hidden = false;
  }

  function notificar(severidad, titulo, texto, enlace, id) {
    if (!estado.activado || !estado.prefs.notificaciones) return;
    if (motivoSinNotificaciones()) {
      pintarNota();
      return;
    }
    var etiqueta = ETIQUETA_SEV[severidad] || "Alerta";
    try {
      var avisoNavegador = new window.Notification("Batrade · " + etiqueta, {
        body: texto ? String(titulo) + " — " + String(texto) : String(titulo),
        tag: "batrade-alerta-" + String(id),
        silent: true  // el tono lo pone Web Audio; no se duplica
      });
      avisoNavegador.onclick = function () {
        window.focus();
        if (enlace) window.location.assign(enlace);
        avisoNavegador.close();
      };
    } catch (error) {
      // Si el navegador rechaza la notificación, el pop-up ya está en pantalla.
    }
  }

  function contarNoVistas(cantidad) {
    estado.noVistas += cantidad;
    pintarTitulo();
  }

  function pintarTitulo() {
    document.title = estado.noVistas > 0
      ? "(" + estado.noVistas + ") Batrade"
      : estado.tituloOriginal;
  }

  function limpiarNoVistas() {
    if (!estado.noVistas) return;
    estado.noVistas = 0;
    pintarTitulo();
  }

  // Si la preferencia "activado" sobrevivió a la recarga, el primer gesto en la
  // página es lo que desbloquea el audio.
  function desbloquearConGesto() {
    if (!estado.activado || estado.audio || !estado.prefs.sonido) return;
    contextoAudio();
  }
  document.addEventListener("click", desbloquearConGesto);
  document.addEventListener("keydown", desbloquearConGesto);

  document.addEventListener("visibilitychange", function () {
    window.clearTimeout(estado.temporizador);
    if (document.hidden) {
      estado.espera = intervalo();
      if (!estado.detenido) programar(estado.espera);
      return;
    }
    // Al volver a la pestaña, el contador del título se limpia y se sondea ya.
    limpiarNoVistas();
    if (estado.detenido) return;
    estado.espera = intervalo();
    sondear();
  });

  window.addEventListener("focus", limpiarNoVistas);

  cargarPrefs();
  conectarControles();
  pintarInterruptor();
  pintarNota();
  sondear();
}());
