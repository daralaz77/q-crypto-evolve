"""Perfiles de protocolo QKD: qué afirma cada familia, qué testigo verificable exige y qué confianza supone.

IMPORTANTE (límite de honestidad): este módulo NO implementa física cuántica y NO puede comprobar que un
dispositivo diga la verdad. Valida (a) que el dispositivo DECLARE los testigos que su protocolo exige,
(b) que los valores sean físicamente posibles, (c) que superen los umbrales de la política o de la ficha
técnica aprobada por una persona, y (d) que el modelo de confianza alcance el mínimo exigido.
Cada familia aporta una idea de diseño distinta (no se copia ningún protocolo):

- BB84 (decoy-state):  testigo estadístico QBER + parámetro de seguridad de clave finita ε + amplificación
                       de privacidad declarada. → umbral de QBER, ε máximo, "sin PA no hay clave".
- E91:                 testigo independiente de la afirmación del dispositivo: violación de Bell/CHSH
                       (S > 2 clásico, S ≤ 2√2 cota de Tsirelson). → rechazar valores imposibles y S ≤ 2+margen.
- MDI-QKD:             el nodo de medida/relé es NO confiable y cierra canales de los detectores. → el relé no
                       es un tenedor de claves; se modela como observador hostil; "trust minimization".
- TF-QKD:              alcance sin repetidores de confianza (error de fase como testigo). → contar saltos de nodos
                       de confianza y limitarlos por política; umbrales dependientes del equipo vienen de su ficha.
- CV-QKD:              hardware de telecomunicaciones, ruido en exceso ξ y calibración del ruido de disparo
                       (superficie de ataque conocida). → umbral de ξ ligado a la ficha aprobada; exigir calibración.
- DI-QKD:              seguridad sin confiar en el hardware: prueba de Bell SIN lagunas. → techo de la escala de
                       garantía; hoy ningún adaptador debería calificar sin pruebas extraordinarias.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from enum import Enum, IntEnum

from ..core.policy import Policy

TSIRELSON = 2 * math.sqrt(2)  # cota cuántica del CHSH (hecho matemático, no un parámetro)
CLASSICAL_CHSH = 2.0  # cota de cualquier teoría local


class QKDProtocol(str, Enum):
    BB84 = "BB84"
    E91 = "E91"
    MDI = "MDI-QKD"
    TF = "TF-QKD"
    CV = "CV-QKD"
    DI = "DI-QKD"
    ETSI_014 = "ETSI-014-KME"   # gestor de claves (KME) accesible por ETSI GS QKD 014: la interfaz NO expone testigos físicos
    UNKNOWN = "UNKNOWN"


class Assurance(IntEnum):
    """Escala de garantía por MODELO DE CONFIANZA (no por 'calidad' del equipo)."""
    NONE = 0  # sin perfil: no se confía en afirmaciones
    TRUSTED_DEVICES = 1  # preparar-y-medir con equipos (incl. detectores) de confianza: BB84, TF, CV
    ENTANGLEMENT_WITNESSED = 2  # E91: la correlación se comprueba con un testigo propio
    MEASUREMENT_DEVICE_INDEPENDENT = 3  # MDI: detectores/relé fuera de la base de confianza
    DEVICE_INDEPENDENT = 4  # DI: ni la fuente ni los detectores son de confianza (experimental)


@dataclass(frozen=True)
class Profile:
    protocol: QKDProtocol
    assurance: Assurance
    witnesses: tuple[str, ...]  # claves que el dispositivo DEBE aportar por cada clave
    relay_untrusted: bool = False  # el relé/nodo central no es tenedor de claves
    per_key_witnesses: bool = True  # False = los testigos no describen cada clave (p. ej. un KME): no se exige ligar la evidencia a la clave
    needs_spec: tuple[str, ...] = ()  # umbrales que solo puede dar la ficha aprobada del equipo
    note: str = ""


COMMON = ("key_id", "epsilon", "privacy_amplification")
PROFILES: dict[QKDProtocol, Profile] = {p.protocol: p for p in (
    Profile(QKDProtocol.BB84, Assurance.TRUSTED_DEVICES, COMMON + ("qber", "decoy_ok", "trusted_hops")),
    Profile(QKDProtocol.E91, Assurance.ENTANGLEMENT_WITNESSED, COMMON + ("qber", "chsh_s", "trusted_hops"),
            note="CHSH certifica correlaciones, no elimina por sí solo las lagunas del montaje"),
    Profile(QKDProtocol.MDI, Assurance.MEASUREMENT_DEVICE_INDEPENDENT, COMMON + ("qber", "decoy_ok", "trusted_hops", "relay_holds_key"),
            relay_untrusted=True),
    Profile(QKDProtocol.TF, Assurance.TRUSTED_DEVICES, COMMON + ("qber", "phase_error", "decoy_ok", "trusted_hops"),
            needs_spec=("phase_error_max",)),
    Profile(QKDProtocol.CV, Assurance.TRUSTED_DEVICES, COMMON + ("excess_noise", "shot_noise_calibrated", "trusted_hops"),
            needs_spec=("excess_noise_max",)),
    Profile(QKDProtocol.DI, Assurance.DEVICE_INDEPENDENT, COMMON + ("qber", "chsh_s", "loophole_free", "trusted_hops"),
            note="experimental: exige prueba de Bell sin lagunas"),
    Profile(QKDProtocol.ETSI_014, Assurance.TRUSTED_DEVICES, ("key_size_bits",), needs_spec=("trusted_hops",), per_key_witnesses=False,
            note="la interfaz 014 solo entrega claves: no hay QBER, ε ni amplificación que comprobar. Se confía en el operador del KME y en su ficha aprobada "
                 "(saltos de confianza); nada de esto es una garantía física"),
)}
UNKNOWN_PROFILE = Profile(QKDProtocol.UNKNOWN, Assurance.NONE, ())


def profile_for(protocol: str) -> Profile:
    try:
        return PROFILES.get(QKDProtocol(protocol), UNKNOWN_PROFILE)
    except ValueError:
        return UNKNOWN_PROFILE


@dataclass(frozen=True)
class Finding:
    kind: str  # "invalid" (imposible/ausente) | "anomaly" (sospecha de espionaje) | "policy" (no cumple la política)
    message: str


def _num(x) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool) and x == x and x not in (math.inf, -math.inf)


def evaluate(profile: Profile, evidence: dict, policy: Policy, key_id: str | None = None,
             spec: dict | None = None) -> list[Finding]:
    """Devuelve TODOS los problemas (lista vacía = el perfil se satisface). Falla cerrado ante ausencias."""
    out: list[Finding] = []
    if profile.assurance < Assurance(policy.min_assurance) or profile.assurance == Assurance.NONE:
        return [Finding("policy", f"{profile.protocol.value}: garantía {profile.assurance.name} < mínimo {Assurance(policy.min_assurance).name}")]
    missing = [w for w in profile.witnesses if w not in evidence]
    if missing:
        return [Finding("invalid", f"faltan testigos exigidos por {profile.protocol.value}: {missing}")]
    if key_id is not None and profile.per_key_witnesses and evidence["key_id"] != key_id:
        out.append(Finding("invalid", "los testigos no corresponden a esta clave (¿reutilización de evidencia?)"))
    # --- clave finita y amplificación de privacidad (BB84 y familia) ---
    if "epsilon" in profile.witnesses:
        eps = evidence["epsilon"]
        if not _num(eps) or not 0 < eps < 1:
            out.append(Finding("invalid", "ε (parámetro de seguridad de clave finita) inválido"))
        elif eps > policy.max_epsilon:
            out.append(Finding("policy", f"ε={eps:g} > máximo de la política {policy.max_epsilon:g}"))
    if "privacy_amplification" in profile.witnesses and evidence["privacy_amplification"] is not True:
        out.append(Finding("policy", "el dispositivo no declara amplificación de privacidad: no es clave utilizable"))
    # --- confianza en nodos intermedios (testigo del dispositivo, o ficha aprobada si el perfil no lo reporta) ---
    hops = evidence["trusted_hops"] if "trusted_hops" in profile.witnesses else (spec or {}).get("trusted_hops")
    if hops is None and "trusted_hops" not in profile.witnesses:
        pass  # el dato debe venir de la ficha aprobada: su ausencia la informa el bucle de `needs_spec` (política), no como respuesta inválida
    elif not isinstance(hops, int) or isinstance(hops, bool) or hops < 0:
        out.append(Finding("invalid", "trusted_hops inválido"))
    elif hops > policy.max_trusted_hops:
        out.append(Finding("policy", f"{hops} saltos por nodos de confianza > máximo {policy.max_trusted_hops}: cada uno ve la clave"))
    if profile.relay_untrusted and evidence.get("relay_holds_key") is not False:
        out.append(Finding("anomaly", "el relé MDI declara (o no niega) conocer la clave: contradice el modelo de confianza"))
    # --- QBER ---
    if "qber" in profile.witnesses:
        q = evidence["qber"]
        if not _num(q) or not 0.0 <= q <= 0.5:
            out.append(Finding("invalid", "QBER fuera de rango físico"))
        elif q >= policy.qber_abort:
            out.append(Finding("anomaly", f"QBER {q:.3f} ≥ {policy.qber_abort}: posible espionaje"))
    # --- CHSH (E91 / DI) ---
    if "chsh_s" in profile.witnesses:
        s = evidence["chsh_s"]
        if not _num(s) or s < 0 or s > TSIRELSON + 1e-9:
            out.append(Finding("invalid", f"CHSH {s!r} imposible (cota de Tsirelson {TSIRELSON:.4f}): dispositivo defectuoso o mentiroso"))
        elif s <= CLASSICAL_CHSH + policy.chsh_margin:
            out.append(Finding("anomaly", f"CHSH {s:.3f} ≤ {CLASSICAL_CHSH + policy.chsh_margin:.2f}: no certifica correlaciones cuánticas"))
    if "loophole_free" in profile.witnesses and evidence["loophole_free"] is not True:
        out.append(Finding("policy", "DI-QKD sin prueba de Bell libre de lagunas: no cumple su propio modelo"))
    if "key_size_bits" in profile.witnesses:
        ksb = evidence["key_size_bits"]
        if not isinstance(ksb, int) or isinstance(ksb, bool) or ksb < 128 or ksb % 8:
            out.append(Finding("policy", "tamaño de clave del KME por debajo de 128 bits o no múltiplo de 8"))
    # --- decoy ---
    if "decoy_ok" in profile.witnesses and evidence["decoy_ok"] is not True:
        out.append(Finding("anomaly", "estadística de estados señuelo inconsistente (posible ataque de número de fotones)"))
    # --- umbrales que solo da la ficha técnica aprobada ---
    for need in profile.needs_spec:
        if not spec or not _num(spec.get(need)):
            out.append(Finding("policy", f"falta {need} en la ficha aprobada del equipo: no se inventa un umbral"))
    if "phase_error" in profile.witnesses and spec and _num(spec.get("phase_error_max")):
        pe = evidence["phase_error"]
        if not _num(pe) or not 0 <= pe <= 0.5:
            out.append(Finding("invalid", "error de fase fuera de rango"))
        elif pe > spec["phase_error_max"]:
            out.append(Finding("anomaly", f"error de fase {pe:.3f} > {spec['phase_error_max']} de la ficha"))
    if "excess_noise" in profile.witnesses:
        if evidence["shot_noise_calibrated"] is not True:
            out.append(Finding("anomaly", "calibración del ruido de disparo no verificada (superficie de ataque conocida de CV-QKD)"))
        xi = evidence["excess_noise"]
        if not _num(xi) or xi < 0:
            out.append(Finding("invalid", "ruido en exceso inválido"))
        elif spec and _num(spec.get("excess_noise_max")) and xi > spec["excess_noise_max"]:
            out.append(Finding("anomaly", f"ruido en exceso {xi:.4f} > {spec['excess_noise_max']} de la ficha"))
    return out
