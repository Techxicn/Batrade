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

  var estado = {
    cursor: null,             // id del último evento warn/crit entregado
    vistos: Object.create(null),
    temporizador: null,
    espera: POLL_MS,
    detenido: false
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
    // Una ráfaga no puede tapar el panel: un solo aviso con el recuento.
    if (eventos.length > RAFAGA_MAX) {
      var peor = "warn";
      for (var i = 0; i < eventos.length; i++) {
        if (eventos[i].severidad === "crit") peor = "crit";
      }
      aviso(peor, eventos.length + " alertas nuevas",
        "Se agruparon para no tapar el panel.", destino);
      return;
    }
    for (var j = 0; j < eventos.length; j++) {
      var ev = eventos[j];
      aviso(ev.severidad, ev.tipo || "Alerta", ev.resumen || null, destino);
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

  document.addEventListener("visibilitychange", function () {
    window.clearTimeout(estado.temporizador);
    if (estado.detenido) return;
    estado.espera = intervalo();
    if (document.hidden) {
      programar(estado.espera);
    } else {
      sondear();
    }
  });

  sondear();
}());
