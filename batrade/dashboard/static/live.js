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
