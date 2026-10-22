"""El localizador de `openssl` de las pruebas: antes las rutas de Homebrew estaban escritas a mano y en Linux las pruebas se saltaban en silencio (INC-0031)."""
import os
import stat

import openssl_tool as T


def fake(tmp_path, name, banner):
    exe = tmp_path / name
    exe.write_text(f"#!/bin/sh\necho '{banner}'\n")
    exe.chmod(exe.stat().st_mode | stat.S_IXUSR)
    return exe


def isolate(monkeypatch, tmp_path):
    monkeypatch.setattr(T, "_HOMEBREW", ())
    monkeypatch.setenv("PATH", str(tmp_path))


def test_an_openssl_3_5_in_the_path_is_found_even_without_homebrew(monkeypatch, tmp_path):
    isolate(monkeypatch, tmp_path)
    exe = fake(tmp_path, "openssl", "OpenSSL 3.5.7 9 Jun 2026 (Library: OpenSSL 3.5.7 9 Jun 2026)")
    assert T.find_openssl() == str(exe)


def test_libressl_and_old_openssl_are_rejected_because_they_have_neither_the_hybrid_group_nor_slh_dsa(monkeypatch, tmp_path):
    isolate(monkeypatch, tmp_path)
    fake(tmp_path, "openssl", "LibreSSL 3.3.6")                         # el openssl de macOS
    assert T.find_openssl() is None
    fake(tmp_path, "openssl", "OpenSSL 3.4.1 11 Feb 2025")              # anterior a ML-KEM/SLH-DSA en OpenSSL
    assert T.find_openssl() is None
    fake(tmp_path, "openssl", "OpenSSL 3.10.0 1 Jan 2030")              # 3.10 > 3.5: la comparación es numérica, no de texto
    assert T.find_openssl() is not None


def test_a_missing_or_broken_executable_gives_none_instead_of_an_error(monkeypatch, tmp_path):
    isolate(monkeypatch, tmp_path)
    assert T.find_openssl() is None
    (tmp_path / "openssl").write_text("no es un ejecutable")
    os.chmod(tmp_path / "openssl", 0o755)
    assert T.find_openssl() is None
