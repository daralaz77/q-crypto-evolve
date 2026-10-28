// Marca que hay JavaScript y decide el movimiento ANTES de pintar. Por defecto manda la preferencia del sistema
// («reducir movimiento»); el botón «Animaciones» deja que la persona lo cambie a mano (se recuerda si el navegador lo permite).
(function () {
  var d = document.documentElement, pref = null;
  d.classList.add("js");
  try { pref = localStorage.getItem("qce-mov"); } catch (e) { pref = null; }
  var os = matchMedia("(prefers-reduced-motion: reduce)").matches;
  var quiet = pref === "on" ? false : pref === "off" ? true : os;
  if (quiet) d.classList.add("quiet");
  window.QCE_MOV = { quiet: quiet, os: os, set: function (v) { try { localStorage.setItem("qce-mov", v); } catch (e) {} location.reload(); } };
})();
