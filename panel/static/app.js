"use strict";
// Todo el texto se inserta con textContent: ningún dato del libro se interpreta como HTML.
const ETIQ = { pass: "pasa", skipped: "omitida", fail: "falla", failed: "falla", blocked: "bloqueada", resuelto: "resuelto", abierto: "abierto" };
const $ = (sel, root = document) => root.querySelector(sel);

function el(tag, attrs, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === "class") n.className = v; else if (k === "style") n.style.cssText = v; else if (v !== null && v !== undefined) n.setAttribute(k, v);
  }
  for (const k of kids.flat()) if (k !== null && k !== undefined) n.append(k.nodeType ? k : document.createTextNode(String(k)));
  return n;
}
const tag = (estado, texto) => el("span", { class: "tag " + estado }, texto || ETIQ[estado] || estado || "—");
const card = (titulo, ...kids) => el("section", { class: "card" }, el("h2", null, titulo), ...kids);
const fmtEdad = (s) => (s < 3600 ? Math.round(s / 60) + " min" : s < 172800 ? (s / 3600).toFixed(1) + " h" : Math.round(s / 86400) + " días");
const fmtMin = (s) => (s >= 120 ? (s / 60).toFixed(1) + " min" : Math.round(s) + " s");

function banner(d) {
  const mapa = { "aprobado": ["ok", "Release aprobado"], "bloqueado": ["bad", "Bloqueado"], "requiere revisión": ["warn", "Requiere revisión humana"] };
  const [clase, texto] = mapa[d.veredicto] || ["warn", d.veredicto];
  const g5 = d.puertas.find((p) => p.puerta.startsWith("G5"));
  const motivo = g5 && g5.estado !== "pass" ? "Falta la puerta G5: una revisión humana independiente." : "";
  return el("div", { class: "banner " + clase, role: "status" },
    el("strong", null, texto), el("span", { class: "mono" }, d.estado),
    el("span", null, motivo), el("span", { class: "muted" }, "Versión ", d.version || "—", " · release ", el("code", null, d.release_id_puertas || "—")));
}

function vigencia(d) {
  const ok = d.puertas_vigentes;
  const clase = ok ? "ok" : "bad";
  return el("div", { class: "banner " + clase },
    el("strong", null, ok ? "Las puertas corresponden al código actual" : "El código cambió desde las últimas puertas"),
    el("span", { class: "muted" }, "Puertas: ", el("code", null, d.release_id_puertas || "—"), " · Código ahora: ", el("code", null, d.release_id_codigo)),
    ok ? null : el("span", null, "Repite `python -m qce gates`; las firmas anteriores ya no valen."));
}

function puertas(d) {
  return card("Puertas G1–G6", el("div", { class: "rack" }, d.puertas.map((p) =>
    el("div", { class: "slot" }, el("span", { class: "led " + p.estado, "aria-hidden": "true" }),
      el("span", { class: "name" }, p.puerta), el("span", { class: "detail" }, p.detalle), tag(p.estado)))));
}

function metricas(d) {
  const m = d.metricas || {};
  const kpi = (v, l) => el("div", { class: "kpi" }, el("div", { class: "v" }, v), el("div", { class: "l" }, l));
  const mu = d.mutacion;
  return card("Cifras", el("div", { class: "kpis" },
    kpi(m.tests_passed ?? "—", "pruebas superadas"),
    kpi(`${m.incidents_resolved ?? "—"}/${m.incidents_total ?? "—"}`, "incidentes resueltos"),
    kpi(mu ? Number(mu.score).toFixed(2) : "—", "puntuación de mutación"),
    kpi(mu ? `${mu.killed}/${mu.scored}` : "—", "mutantes detectados"),
    kpi(m.total_seconds ? fmtMin(m.total_seconds) : "—", "duración de las puertas")));
}

function tiempos(d) {
  return card("Tiempo por puerta", d.puertas.map((p) =>
    el("div", { class: "row" }, el("span", null, p.puerta),
      el("div", { class: "bar", role: "img", "aria-label": `${p.puerta}: ${p.pct}%` }, el("i", { style: `width:${Math.max(p.pct, 0.5)}%` })),
      el("span", { class: "num" }, fmtMin(p.segundos)))));
}

function cadena(d) {
  const c = d.cadena;
  return card("Libro de incidentes",
    el("p", null, tag(c.ok ? "pass" : "fail"), " ", c.ok ? `Cadena de hashes íntegra: ${c.entradas} entradas.` : `¡Cadena rota! ${c.error}`),
    el("p", { class: "muted" }, "Cabeza: ", el("code", null, c.cabeza.slice(0, 16)), ". Detecta manipulación parcial; quien reescriba toda la cadena sin ancla externa no se detecta (ver LIMITATIONS.md)."));
}

function firmas(d) {
  const filas = d.firmas.map((f) => el("tr", null, el("td", null, f.rol), el("td", null, f.firmante), el("td", null, el("code", null, f.release_id)),
    el("td", null, f.veredicto), el("td", null, f.vigente ? tag("pass", "vigente") : tag("neutral", "otra versión"))));
  return card("Firmas humanas y registro de confianza",
    el("div", { class: "tablewrap" }, el("table", null, el("thead", null, el("tr", null, ["Rol", "Firmante", "Release", "Veredicto", "Estado"].map((h) => el("th", null, h)))), el("tbody", null, filas))),
    el("p", { class: "muted" }, "Identidades registradas: ", d.confianza.map((c) => `${c.nombre} (${c.rol})`).join(", ") || "ninguna",
      ". El panel no verifica firmas: la puerta G6 lo hace con criptografía. Las firmas de «implementer» son declaraciones de autoría, no revisión independiente."));
}

function incidentes(d) {
  const wrap = el("div");
  const sel = el("select", { "aria-label": "Filtrar por estado" }, ["todos", "resuelto", "abierto"].map((v) => el("option", { value: v }, v)));
  const q = el("input", { type: "search", placeholder: "Buscar (módulo, síntoma…)", "aria-label": "Buscar incidentes" });
  const lista = el("div");
  const pintar = () => {
    const txt = q.value.toLowerCase();
    const sub = d.incidentes.filter((i) => (sel.value === "todos" || i.estado === sel.value)
      && (!txt || [i.id, i.modulo, i.sintoma, i.causa].join(" ").toLowerCase().includes(txt)));
    lista.replaceChildren(el("p", { class: "muted" }, `${sub.length} de ${d.incidentes.length}`),
      ...sub.map((i) => el("details", null,
        el("summary", null, el("strong", null, i.id), " ", tag(i.estado), " ", el("span", { class: "muted" }, (i.modulo || "").slice(0, 80))),
        el("dl", { class: "detail-body" },
          el("dt", null, "Síntoma"), el("dd", null, i.sintoma || "—"),
          el("dt", null, "Causa raíz"), el("dd", null, `${i.causa || "—"} (certeza: ${i.certeza || "—"}; categoría: ${i.categoria || "—"})`),
          el("dt", null, "Reparación"), el("dd", null, i.reparacion || "—"),
          el("dt", null, "Prueba de reproducción"), el("dd", null, el("code", null, i.prueba || "—")),
          el("dt", null, "Riesgos residuales"), el("dd", null, String(i.riesgos || "—"))))));
  };
  sel.addEventListener("change", pintar); q.addEventListener("input", pintar); pintar();
  wrap.append(el("div", { class: "filters" }, sel, q), lista);
  return card("Incidentes", wrap);
}

function limites(d) {
  return card("Lo que este sistema NO afirma",
    el("ul", { class: "plain" }, d.no_afirma.map((t) => el("li", null, t))),
    el("p", { class: "muted" }, "Patrones repetidos: ", d.patrones.join(" · ") || "ninguno"));
}

function countUp() {
  if (document.documentElement.classList.contains("quiet")) return;
  document.querySelectorAll(".kpi .v").forEach((b) => {
    const final = b.textContent, m = final.match(/^(\d+)(?![.\d])(.*)$/);
    if (!m) return;
    const target = +m[1], rest = m[2], t0 = performance.now();
    const tick = (t) => { const k = Math.min(1, (t - t0) / 900); b.textContent = Math.round(target * (1 - Math.pow(1 - k, 3))) + rest; if (k < 1) requestAnimationFrame(tick); else b.textContent = final; };
    requestAnimationFrame(tick);
  });
}
function botonMovimiento() {
  const b = $("#mov"), q = window.QCE_MOV.quiet;
  b.textContent = q ? "Animaciones: no" : "Animaciones: sí";
  b.setAttribute("aria-pressed", String(!q));
  b.setAttribute("aria-label", q ? "Animaciones desactivadas. Activarlas" : "Animaciones activadas. Reducirlas");
  b.addEventListener("click", () => window.QCE_MOV.set(q ? "on" : "off"));
}
botonMovimiento();

async function cargar() {
  const app = $("#app");
  try {
    const r = await fetch("/api/estado", { cache: "no-store" });
    if (!r.ok) throw new Error("HTTP " + r.status);
    const d = await r.json();
    app.classList.toggle("enter", !app.dataset.listo); app.dataset.listo = "1";
    app.replaceChildren(banner(d), vigencia(d), puertas(d), el("div", { class: "grid2" }, metricas(d), cadena(d)),
      el("div", { class: "grid2" }, tiempos(d), limites(d)), firmas(d), incidentes(d));
    countUp();
    const edad = d.puertas_antiguedad_s;
    $("#actualizado").textContent = "Puertas calculadas hace " + (edad === null ? "—" : fmtEdad(edad)) + " · leído " + d.generado.slice(11, 19) + " UTC";
  } catch (e) {
    app.replaceChildren(el("p", { class: "banner bad" }, "No se pudo leer el estado: " + e.message));
  }
}
$("#refrescar").addEventListener("click", cargar);
cargar();
