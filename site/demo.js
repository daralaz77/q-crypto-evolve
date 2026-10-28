"use strict";
// Todo con textContent / nodos DOM: nada de lo grabado se interpreta como HTML.
const T = window.TRAZAS;
const $ = (s) => document.querySelector(s);
function el(tag, attrs, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) { if (k === "class") n.className = v; else if (v != null) n.setAttribute(k, v); }
  for (const k of kids.flat()) if (k != null) n.append(k.nodeType ? k : document.createTextNode(String(k)));
  return n;
}
const NS = "http://www.w3.org/2000/svg";
function svg(tag, attrs, text) {
  const n = document.createElementNS(NS, tag);
  for (const [k, v] of Object.entries(attrs || {})) n.setAttribute(k, v);
  if (text != null) n.textContent = text;
  return n;
}

// Explicaciones en lenguaje normal (autoría del proyecto; las trazas, en cambio, son las grabadas tal cual).
const EXPLICA = {
  1: { titulo: "Se enciende un servidor de claves de mentira",
       que: "Un KME es el servidor que reparte claves de un equipo de distribución cuántica de claves (QKD). Aquí es un programa de prueba que habla el mismo idioma (ETSI GS QKD 014), con conexión cifrada y autenticación en los dos sentidos.",
       no: "No hay fotones ni física cuántica. Es una simulación para probar el software que rodea a la clave." },
  2: { titulo: "Un cliente pide una clave y otro la recoge",
       que: "La «SAE maestra» pide una clave y recibe solo su número de identificación (key_ID). La clave en sí no se imprime. La «SAE esclava» la recoge usando ese key_ID: deben acabar con la misma clave.",
       no: "No demuestra que un KME de un fabricante real se comporte igual: solo se probó contra este emulador." },
  3: { titulo: "La clave se usa como contraseña compartida de una conexión segura",
       que: "Con esa clave como PSK (clave precompartida) se abre una conexión TLS 1.3 estándar. El intercambio de claves usa X25519MLKEM768, un grupo híbrido: un algoritmo clásico más uno diseñado para resistir ordenadores cuánticos. Si las dos claves difirieran, la conexión fallaría.",
       no: "La resistencia cuántica descansa en ML-KEM y en OpenSSL, no en este código. El puente que conecta todo es código propio sin revisión humana." },
  4: { titulo: "Cada clave se entrega una sola vez",
       que: "Un segundo intento de recoger la misma clave se rechaza. Una clave reutilizada rompería la seguridad, así que el KME no lo permite.",
       no: "Es una propiedad del emulador y de nuestro cliente; no valida ningún equipo físico." },
};

function diagrama() {
  const quiet = document.documentElement.classList.contains("quiet");
  const box = (x, y, w, t, sub, cls) => [svg("rect", { x, y, width: w, height: 64, rx: 12, class: "nodo " + (cls || "") }),
    svg("text", { x: x + w / 2, y: y + 28, "text-anchor": "middle", fill: "var(--text)", "font-size": 16, "font-weight": 700 }, t),
    svg("text", { x: x + w / 2, y: y + 49, "text-anchor": "middle", fill: "var(--muted)", "font-size": 13 }, sub)];
  const s = svg("svg", { viewBox: "0 0 880 160", "aria-hidden": "true" });
  const cables = [["M200,72 C270,72 280,42 345,42", "①"], ["M200,72 C270,72 280,112 345,112", "②"], ["M535,42 C610,42 620,72 690,72", "③"], ["M535,112 C610,112 620,72 690,72", "③"]];
  cables.forEach(([d, label], i) => {
    s.append(svg("path", { d, fill: "none", class: "cable", id: "cab" + i }));
    if (!quiet) { const c = svg("circle", { r: 5, fill: "var(--accent)" }); const a = svg("animateMotion", { dur: (2.6 + i * .35) + "s", repeatCount: "indefinite", begin: "0s" }); a.append(svg("mpath", { href: "#cab" + i })); c.append(a); s.append(c); }
  });
  [...box(10, 40, 190, "KME simulado", "reparte claves"), ...box(345, 10, 190, "SAE maestra", "pide la clave"), ...box(345, 80, 190, "SAE esclava", "recoge por key_ID"), ...box(690, 40, 180, "TLS 1.3 + PSK", "X25519MLKEM768", "tls")].forEach((n) => s.append(n));
  $("#diagrama").append(s);
}

let actual = 0;
function pintaPaso() {
  const pasos = T.quickstart.pasos;
  const p = pasos[actual], e = EXPLICA[p.n] || { titulo: "Paso " + p.n, que: "", no: "" };
  const cont = el("div", { class: "paso enter" },
    el("h3", null, `Paso ${p.n}. ${e.titulo}`, el("span", { class: "tag-sim" }, "SIMULACIÓN")),
    el("p", null, e.que),
    el("p", { class: "muted" }, "Lo que imprimió el programa (traza real grabada):"),
    ...p.lineas.map((l) => el("div", { class: "trace" }, `[${p.n}] ${l}`)),
    el("p", { class: "notproves" }, el("strong", null, "Lo que esto no prueba: "), e.no),
    p.n === pasos[pasos.length - 1].n ? el("p", { class: "note" }, T.quickstart.cierre) : null);
  $("#paso").replaceChildren(cont);
  $("#progreso").className = "p" + actual;
  document.querySelectorAll("#nav button").forEach((b, i) => b.setAttribute("aria-selected", String(i === actual)));
  $("#ant").disabled = actual === 0; $("#sig").disabled = actual === pasos.length - 1;
}
function stepper() {
  const nav = $("#nav");
  T.quickstart.pasos.forEach((p, i) => {
    const b = el("button", { type: "button", role: "tab", "aria-label": "Paso " + p.n }, p.n);
    b.addEventListener("click", () => { actual = i; pintaPaso(); });
    nav.append(b);
  });
  $("#ant").addEventListener("click", () => { if (actual > 0) { actual--; pintaPaso(); } });
  $("#sig").addEventListener("click", () => { if (actual < T.quickstart.pasos.length - 1) { actual++; pintaPaso(); } });
  document.addEventListener("keydown", (ev) => {
    if (ev.target.closest("input,textarea,select")) return;
    if (ev.key === "ArrowRight") $("#sig").click(); else if (ev.key === "ArrowLeft") $("#ant").click();
  });
  pintaPaso();
}

function fallos() {
  const d = T.demo, n = d.comprobaciones.length, ok = d.comprobaciones.filter((c) => c.ok).length;
  const kpi = (v, l) => el("div", { class: "kpi" }, el("b", null, v), el("span", null, l));
  $("#resumen-demo").append(kpi(`${ok}/${n}`, "comprobaciones correctas"), kpi(d.todo_ok ? "sí" : "no", "demostración completa"),
    kpi(`${Math.round(d.tiempos_s.total)} s`, "duración total"), kpi(`${d.tiempos_s.deteccion_a_incidente} s`, "del fallo al incidente"));
  $("#checks").append(...d.comprobaciones.map((c) => el("li", null, el("details", null,
    el("summary", null, el("span", { class: c.ok ? "ok" : "bad", "aria-label": c.ok ? "correcta" : "fallida" }, c.ok ? "✓" : "✗"), el("span", null, c.check)),
    el("div", { class: "obs" }, c.observed)))));
  $("#limites").append(...["Esto es un laboratorio: no hay despliegue ni claves de producción.", ...d.no_demostrado.map((x) => "No demuestra: " + x + ".")].map((t) => el("li", null, t)));
}
function countUp() {
  const quiet = document.documentElement.classList.contains("quiet");
  document.querySelectorAll(".kpi b").forEach((b) => {
    const final = b.textContent, m = final.match(/^(\d+)(?![.\d])(.*)$/);
    if (quiet || !m) return;
    const target = +m[1], rest = m[2], t0 = performance.now(), dur = 1100;
    b.textContent = "0" + rest;
    const tick = (t) => { const k = Math.min(1, (t - t0) / dur), v = Math.round(target * (1 - Math.pow(1 - k, 3))); b.textContent = v + rest; if (k < 1) requestAnimationFrame(tick); else b.textContent = final; };
    const io = new IntersectionObserver((es) => { if (es[0].isIntersecting) { io.disconnect(); requestAnimationFrame(tick); } });
    io.observe(b);
  });
}
function reveal() {
  const items = document.querySelectorAll("[data-reveal], .checks li");
  if (!("IntersectionObserver" in window)) { items.forEach((i) => i.classList.add("in")); return; }
  const io = new IntersectionObserver((es) => es.forEach((e) => { if (e.isIntersecting) { e.target.classList.add("in"); io.unobserve(e.target); } }), { threshold: 0.08 });
  items.forEach((i, n) => { if (i.matches(".checks li")) i.style.transitionDelay = Math.min(n % 12, 8) * 40 + "ms"; io.observe(i); });
}
function botonMovimiento() {
  const b = $("#mov"), q = window.QCE_MOV.quiet;
  b.textContent = q ? "Animaciones: no · activar" : "Animaciones: sí · reducir";
  b.setAttribute("aria-pressed", String(!q));
  b.setAttribute("aria-label", q ? "Las animaciones están desactivadas. Activar animaciones" : "Las animaciones están activadas. Reducir animaciones");
  b.addEventListener("click", () => window.QCE_MOV.set(q ? "on" : "off"));
}
botonMovimiento(); diagrama(); stepper(); fallos(); countUp(); reveal();
