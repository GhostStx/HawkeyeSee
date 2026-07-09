"""Fixtures partagées pour les tests."""

import os
import tempfile
import pytest


@pytest.fixture
def db_chemin():
    """Crée un chemin temporaire pour la base de test."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        chemin = f.name
    yield chemin
    if os.path.exists(chemin):
        os.unlink(chemin)


@pytest.fixture
def fichier_liste_noire():
    """Crée un fichier de liste noire temporaire."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("# Test blacklist\n")
        f.write("evil.com\n")
        f.write("malware-tracker.example.com\n")
        f.write(".phishing.xyz\n")  # wildcard suffixe
        f.write("*.dynamic.dns\n")  # wildcard
        chemin = f.name
    yield chemin
    if os.path.exists(chemin):
        os.unlink(chemin)
