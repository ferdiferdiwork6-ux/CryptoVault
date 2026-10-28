"""
Tests unitaires pour les modules bonus :
- cryptolib/shamir.py  : partage de secret de Shamir (k parmi n)
- cryptolib/mlkem.py   : ML-KEM (post-quantique, NIST 2024) + comparaison ECDH
"""
from __future__ import annotations
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from cryptolib.shamir import (
    partager_secret, reconstruire_secret,
    partager_cle_bytes, reconstruire_cle_bytes,
    _P,
)
from cryptolib.mlkem import (
    mlkem_generer_cle, mlkem_encapsuler, mlkem_decapsuler,
    comparer_ecdh_mlkem, echange_hybride_x25519_mlkem,
    NIVEAUX,
)


# ═══════════════════════════════════════════════════════════════════════════
# SHAMIR
# ═══════════════════════════════════════════════════════════════════════════

class TestShamir:

    def test_reconstruction_exactement_k(self):
        """k parts exactement suffisent à reconstruire le secret."""
        secret = 123456789
        parts  = partager_secret(secret, k=3, n=5)
        assert reconstruire_secret(parts[:3]) == secret

    def test_reconstruction_plus_de_k(self):
        """Plus de k parts donnent aussi le bon secret."""
        secret = 987654321
        parts  = partager_secret(secret, k=2, n=5)
        assert reconstruire_secret(parts[:4]) == secret
        assert reconstruire_secret(parts)     == secret

    def test_moins_de_k_ne_reconstruit_pas(self):
        """k-1 parts ne doivent pas donner le secret."""
        secret = 42
        parts  = partager_secret(secret, k=3, n=5)
        faux   = reconstruire_secret(parts[:2])
        assert faux != secret

    def test_n_egal_k(self):
        """Cas limite n = k : toutes les parts nécessaires."""
        secret = 99999
        parts  = partager_secret(secret, k=4, n=4)
        assert reconstruire_secret(parts) == secret

    def test_k_egal_2(self):
        """Cas minimal k=2 : deux parts suffisent."""
        secret = 7
        parts  = partager_secret(secret, k=2, n=10)
        for i in range(len(parts)):
            for j in range(i+1, len(parts)):
                assert reconstruire_secret([parts[i], parts[j]]) == secret

    def test_parts_non_sequentielles(self):
        """Les parts 1, 3, 5 (non consécutives) reconstruisent le secret."""
        secret = 55555
        parts  = partager_secret(secret, k=3, n=5)
        assert reconstruire_secret([parts[0], parts[2], parts[4]]) == secret

    def test_secret_zero(self):
        parts = partager_secret(0, k=2, n=3)
        assert reconstruire_secret(parts[:2]) == 0

    def test_grand_secret(self):
        """Secret de 256 bits."""
        secret = int.from_bytes(os.urandom(32), "big") % _P
        parts  = partager_secret(secret, k=3, n=5)
        assert reconstruire_secret(parts[:3]) == secret

    def test_parts_aleatoires_differentes(self):
        """Deux appels avec le même secret produisent des parts différentes."""
        secret = 12345
        parts1 = partager_secret(secret, k=2, n=3)
        parts2 = partager_secret(secret, k=2, n=3)
        assert parts1 != parts2

    def test_k_invalide(self):
        with pytest.raises(ValueError):
            partager_secret(1, k=1, n=3)

    def test_n_inferieur_k(self):
        with pytest.raises(ValueError):
            partager_secret(1, k=3, n=2)

    def test_secret_trop_grand(self):
        with pytest.raises(ValueError):
            partager_secret(_P + 1, k=2, n=3)

    # ── Partage de clé bytes ──────────────────────────────────────────────

    def test_partager_cle_bytes_aller_retour(self):
        cle   = os.urandom(32)
        parts = partager_cle_bytes(cle, k=3, n=5)
        recup = reconstruire_cle_bytes(parts[:3], longueur_octets=32)
        assert recup == cle

    def test_partager_cle_aes_256(self):
        """Cas concret : clé de l'AC racine partagée entre 5 admins (seuil 3)."""
        cle_racine = os.urandom(32)
        parts = partager_cle_bytes(cle_racine, k=3, n=5)
        assert len(parts) == 5
        # 3 admins quelconques peuvent reconstruire
        for trio in [(0,1,2), (0,1,4), (1,3,4), (0,2,4)]:
            trois_parts = [parts[i] for i in trio]
            assert reconstruire_cle_bytes(trois_parts, 32) == cle_racine

    def test_deux_admins_insuffisants(self):
        """2 admins sur 5 ne doivent pas retrouver la clé (seuil 3).
        Avec k-1 parts, la reconstruction de Lagrange donne un résultat
        erroné (soit une valeur différente, soit un entier hors intervalle)."""
        cle   = os.urandom(32)
        parts = partager_cle_bytes(cle, k=3, n=5)
        try:
            faux = reconstruire_cle_bytes(parts[:2], 32)
            # Si pas d'erreur, le résultat doit être différent du secret
            assert faux != cle
        except (OverflowError, ValueError):
            # OverflowError = résultat > p, pas convertible en 32 octets
            # C'est la preuve que les 2 parts ne suffisent pas
            pass


# ═══════════════════════════════════════════════════════════════════════════
# ML-KEM
# ═══════════════════════════════════════════════════════════════════════════

class TestMLKEM:

    @pytest.mark.parametrize("niveau", ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"])
    def test_keygen_encaps_decaps(self, niveau):
        """Encapsulation + décapsulation doit produire le même secret."""
        ek, dk       = mlkem_generer_cle(niveau)
        secret_a, ct = mlkem_encapsuler(ek, niveau)
        secret_b     = mlkem_decapsuler(dk, ct, niveau)
        assert secret_a == secret_b, f"Secrets différents pour {niveau}"

    @pytest.mark.parametrize("niveau", ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"])
    def test_secret_32_octets(self, niveau):
        ek, dk       = mlkem_generer_cle(niveau)
        secret, _    = mlkem_encapsuler(ek, niveau)
        assert len(secret) == 32

    def test_cles_differentes_a_chaque_appel(self):
        ek1, _ = mlkem_generer_cle("ML-KEM-768")
        ek2, _ = mlkem_generer_cle("ML-KEM-768")
        assert ek1 != ek2

    def test_mauvaise_cle_privee_secret_different(self):
        """Décapsuler avec la mauvaise clé privée donne un secret différent."""
        ek_a, dk_a = mlkem_generer_cle("ML-KEM-512")
        _, dk_b    = mlkem_generer_cle("ML-KEM-512")
        secret_a, ct = mlkem_encapsuler(ek_a, "ML-KEM-512")
        # ML-KEM est IND-CCA2 : décapsuler avec la mauvaise clé retourne un
        # secret pseudo-aléatoire différent (pas d'erreur levée par conception)
        secret_faux = mlkem_decapsuler(dk_b, ct, "ML-KEM-512")
        assert secret_faux != secret_a

    def test_tailles_cles_768(self):
        """Vérifier les tailles de clés ML-KEM-768 (FIPS 203)."""
        ek, dk = mlkem_generer_cle("ML-KEM-768")
        # ML-KEM-768 : ek = 1184 octets, dk = 2400 octets
        assert len(ek) == 1184
        assert len(dk) == 2400

    def test_tailles_ciphertext_768(self):
        ek, _ = mlkem_generer_cle("ML-KEM-768")
        _, ct = mlkem_encapsuler(ek, "ML-KEM-768")
        # ML-KEM-768 : ciphertext = 1088 octets
        assert len(ct) == 1088

    # ── Comparaison ECDH vs ML-KEM ────────────────────────────────────────

    def test_comparaison_retourne_deux_entrees(self):
        res = comparer_ecdh_mlkem(n_essais=2)
        assert "ECDH P-256"  in res
        assert "ML-KEM-768"  in res

    def test_comparaison_secrets_corrects(self):
        res = comparer_ecdh_mlkem(n_essais=2)
        for nom, stats in res.items():
            assert stats["taille_secret_octets"] == 32
            assert stats["temps_echange_ms"] > 0

    def test_mlkem_resistance_quantique(self):
        res = comparer_ecdh_mlkem(n_essais=1)
        assert not res["ECDH P-256"]["resistance_quantique"]
        assert res["ML-KEM-768"]["resistance_quantique"]

    def test_mlkem_cle_pub_plus_grande_que_ecdh(self):
        """ML-KEM a des clés plus grandes qu'ECDH — coût du post-quantique."""
        res = comparer_ecdh_mlkem(n_essais=1)
        assert (res["ML-KEM-768"]["taille_cle_pub_octets"] >
                res["ECDH P-256"]["taille_cle_pub_octets"])

    # ── Échange hybride ───────────────────────────────────────────────────

    def test_hybride_secrets_egaux(self):
        h = echange_hybride_x25519_mlkem()
        assert h["secrets_ecdh_egaux"]
        assert h["secrets_mlkem_egaux"]
        assert h["cles_hybrides_egales"]

    def test_hybride_cle_32_octets(self):
        h = echange_hybride_x25519_mlkem()
        assert h["taille_cle_finale"] == 32   # AES-256
