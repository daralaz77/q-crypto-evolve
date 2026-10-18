"""Excepciones del sistema. Todas heredan de QCEError para poder clasificarlas."""


class QCEError(Exception):
    """Base de todos los errores controlados."""


class PolicyViolation(QCEError):
    """La operación viola la política criptográfica (degradación, parámetros, etc.)."""


class AuthenticationFailure(QCEError):
    """Firma, MAC o etiqueta AEAD inválida."""


class ReplayDetected(QCEError):
    """Mensaje repetido o fuera de la ventana permitida."""


class KeyStateError(QCEError):
    """Uso de una clave en un estado o con un propósito no permitido."""


class MalformedMessage(QCEError):
    """Mensaje que no cumple el formato estricto."""


class QKDAnomaly(QCEError):
    """El canal QKD muestra señales de espionaje o la fuente no es admisible."""


class IntegrityError(QCEError):
    """Registro de auditoría, manifiesto o almacén manipulado."""
