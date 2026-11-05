# Accesos, identidades y avisos de seguridad

Registro de **quién y qué tiene acceso** al proyecto, y de **qué avisos de seguridad se siguen**. Responde a los capítulos «Updated Knowledgebase…» y «Up to Date Security» de la [guía de buenas prácticas de OSTIF](https://github.com/ostif-org/best-practices-guide). Estado verificado el **2026-11-05** con la API de GitHub; si algo cambia, se actualiza este archivo en el mismo cambio. No contiene secretos: solo nombres y ubicaciones.

## 1. Accesos al repositorio (GitHub)

| Elemento | Estado | Nota |
|---|---|---|
| Personas con acceso | 1: `daralaz77` (rol *admin*) | Única persona mantenedora. No hay otros colaboradores. |
| Secretos de GitHub Actions | **Ninguno** | Los flujos usan solo el `GITHUB_TOKEN` efímero y permisos mínimos por trabajo. |
| Claves de despliegue (*deploy keys*) | **Ninguna** | |
| Webhooks | 1: `zenodo.org`, evento `release` | Parece la integración estándar de Zenodo con GitHub (se dispara con cada *release*; no confirmado por ser configuración externa). No recibe secretos. |
| GitHub Pages | Activo | Demo estática (`pages.yml`): `https://daralaz77.github.io/q-crypto-evolve/` |
| Protección de `main` | Activa desde 2026-11-05 | Ver el apartado 4. |

Controles de GitHub activados: reporte privado de vulnerabilidades, Dependabot (alertas y actualizaciones de seguridad), escaneo de secretos y **protección contra subida de secretos**, CodeQL, OpenSSF Scorecard y zizmor (en CI).

## 2. Identidades de firma (ceremonia G5/G6)

Registradas en `trust/registry.json` (solo claves **públicas**):

| Identidad | Rol | Qué puede firmar |
|---|---|---|
| `darwing` | `approver` | La autorización humana (G6) sobre un `release_id` exacto. |
| `claude-implementer` | `implementer` | La declaración del implementador (G5). No puede ser también el revisor. |

- No hay ningún `reviewer` registrado: **G5 (revisión independiente) sigue pendiente**.
- La clave privada de `darwing` vive **fuera del repositorio**, en el equipo de la persona mantenedora, con permisos `0600`. Nunca se entrega a un agente ni a la CI.
- Cualquier cambio en `qce/` o `tests/` cambia el `release_id` e invalida las firmas anteriores.

## 3. Otros accesos que afectan al proyecto

- **Correo de seguridad:** `director@daralaz.com` (alternativa de `SECURITY.md`). La persona mantenedora controla ese buzón.
- **Sitio `daralaz.com`:** donde iría `/.well-known/security.txt` (ver `docs/security.txt.propuesto`). Se despliega aparte de este repositorio.
- **Solicitud de financiación:** `funding.json` en la raíz.

## 4. Protección de la rama `main`

Activa desde el 2026-11-05 (configuración de GitHub, no del repositorio):
- **No se puede borrar ni reescribir** (sin *force push*).
- Los cambios que entran por *pull request* deben pasar las pruebas de CI **«Debian 13 x86_64»** y **«Debian 13 arm64»**.
- **No se exige aprobación de otra persona** (no existe: hay una sola mantenedora) y **no se aplica a administradores**: la persona mantenedora puede seguir subiendo directo, por ejemplo los registros de las puertas.
- Para quitarla: `gh api -X DELETE repos/daralaz77/q-crypto-evolve/branches/main/protection`.

Límite declarado: sin revisión de otra persona, OpenSSF Scorecard seguirá marcando `CodeReview` en 0. La revisión independiente (G5) es lo que lo cubriría.

## 5. Avisos de seguridad a seguir

El puente TLS del proyecto depende de **OpenSSL ≥ 3.5** y de `cryptography`; además se prueba contra NSS, GnuTLS y SoftHSM. Un aviso de cualquiera de ellos puede afectar a este proyecto aunque no cambie su código. Quien mantiene el proyecto debe estar suscrito a:

| Componente | Dónde seguir los avisos |
|---|---|
| OpenSSL | Listas de correo: <https://openssl-library.org/community/mailinglists/> (anuncios) · Vulnerabilidades: <https://openssl-library.org/news/vulnerabilities/> |
| `pyca/cryptography` | Avisos de GitHub: <https://github.com/pyca/cryptography/security/advisories> (en el repositorio, *Watch → Custom → Security alerts*) |
| GnuTLS | <https://www.gnutls.org/security-new.html> |
| NSS | <https://www.mozilla.org/en-US/security/advisories/> (los avisos de NSS salen con los de Mozilla) |
| SoftHSM | <https://github.com/softhsm/SoftHSMv2/security> |
| Python | Avisos de la versión en uso (3.13 en CI, 3.14 en desarrollo) |
| Este repositorio | Alertas de Dependabot y de *code scanning* (ya activas) |

**Qué se hace cuando llega un aviso que nos afecta:** se sigue `docs/RESPUESTA_A_INCIDENTES.md` (apartado B para componentes de terceros): comprobar la versión instalada, registrar el incidente, actualizar y repetir las puertas.

> **Estado:** estas suscripciones las tiene que hacer la persona mantenedora con su propia cuenta; este archivo solo las lista. *Pendiente de confirmar por la persona mantenedora.*

## 6. Cuándo revisar este archivo

Al añadir una persona colaboradora, un secreto, una clave o una integración; al rotar una clave; y antes de cada auditoría externa.
