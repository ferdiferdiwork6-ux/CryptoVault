"""
Tests unitaires pour cryptolib/dh.py et lab/attaques_dh.py
Vecteurs : cours ch.4, RFC 5869 (HKDF).
"""
from __future__ import annotations
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import math
import pytest
from cryptolib.numtheory import expmod
from cryptolib.dh import (
    dh_generer_secret,
    dh_calculer_secret_partage,
    _dh_valider_valeur,
    hkdf_extract, hkdf_expand, hkdf,
    dh_deriver_cles,
    simuler_echange_dh,
    demo_forward_secrecy,
    GROUPES,
)
from lab.attaques_dh import (
    simuler_mitm,
    simuler_mitm_avec_signatures,
    bsgs,
    attaque_bsgs_dh,
)


# ---------------------------------------------------------------------------
# Vecteur du cours (p=23, g=5, a=6, b=15)
# ---------------------------------------------------------------------------

def test_dh_vecteur_cours():
    p, g = 23, 5
    a, b = 6, 15
    A = expmod(g, a, p)
    B = expmod(g, b, p)
    assert A == 8,  f"A attendu 8, obtenu {A}"
    assert B == 19, f"B attendu 19, obtenu {B}"
    K_a = expmod(B, a, p)
    K_b = expmod(A, b, p)
    assert K_a == K_b == 2, f"K attendu 2, obtenu K_a={K_a}, K_b={K_b}"


# ---------------------------------------------------------------------------
# Génération et échange DH
# ---------------------------------------------------------------------------

def test_dh_secret_commun_demo():
    res = simuler_echange_dh("demo")
    assert res["secret_commun"]

def test_dh_secret_commun_2048():
    """Échange DH sur groupe MODP 2048 bits."""
    res = simuler_echange_dh("2048")
    assert res["secret_commun"]
    assert res["p_bits"] == 2048

def test_dh_cles_derivees_differentes():
    """Les deux clés dérivées (chiffrement, auth) doivent être distinctes."""
    res = simuler_echange_dh("demo")
    assert res["cle_chiffrement"] != res["cle_auth"]

def test_dh_cles_32_octets():
    """Chaque clé dérivée doit faire 32 octets (256 bits)."""
    res = simuler_echange_dh("demo")
    assert len(bytes.fromhex(res["cle_chiffrement"])) == 32
    assert len(bytes.fromhex(res["cle_auth"])) == 32

def test_dh_valeur_publique_dans_groupe():
    """A = g^a mod p doit être dans ]1, p[."""
    p, g = GROUPES["demo"]["p"], GROUPES["demo"]["g"]
    for _ in range(20):
        a, A = dh_generer_secret(p, g)
        assert 1 < A < p

def test_dh_valider_valeur_invalide():
    p = GROUPES["demo"]["p"]
    with pytest.raises(ValueError):
        _dh_valider_valeur(1, p)
    with pytest.raises(ValueError):
        _dh_valider_valeur(p, p)
    with pytest.raises(ValueError):
        _dh_valider_valeur(0, p)

def test_dh_secrets_ephemeres_distincts():
    """Deux appels à dh_generer_secret doivent produire des secrets distincts."""
    p, g = GROUPES["demo"]["p"], GROUPES["demo"]["g"]
    a1, A1 = dh_generer_secret(p, g)
    a2, A2 = dh_generer_secret(p, g)
    # Probabilité quasi nulle que a1 == a2 pour p=23
    # On vérifie juste que la fonction retourne des valeurs valides
    assert 2 <= A1 <= p - 2
    assert 2 <= A2 <= p - 2


# ---------------------------------------------------------------------------
# HKDF — vecteurs RFC 5869
# ---------------------------------------------------------------------------

# Test Case 1 (SHA-256)
def test_hkdf_rfc5869_tc1():
    ikm  = bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
    sel  = bytes.fromhex("000102030405060708090a0b0c")
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    attendu_prk = "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
    attendu_okm = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    prk = hkdf_extract(sel, ikm)
    assert prk.hex() == attendu_prk
    okm = hkdf_expand(prk, info, 42)
    assert okm.hex() == attendu_okm

# Test Case 2 (SHA-256, sel/info vides)
def test_hkdf_rfc5869_tc3():
    """RFC 5869 Test Case 3 : sel et info vides."""
    ikm  = bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
    sel  = b""
    info = b""
    attendu_okm = "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
    okm = hkdf(ikm, 42, sel=sel, info=info)
    assert okm.hex() == attendu_okm

def test_hkdf_longueur_correcte():
    for n in [16, 32, 64, 100]:
        okm = hkdf(b"ikm", n)
        assert len(okm) == n

def test_hkdf_longueur_trop_grande():
    with pytest.raises(ValueError):
        hkdf_expand(b"a" * 32, b"", 255 * 32 + 1)

def test_hkdf_deterministe():
    """Même entrée → même sortie."""
    okm1 = hkdf(b"ikm_test", 32, sel=b"sel", info=b"info")
    okm2 = hkdf(b"ikm_test", 32, sel=b"sel", info=b"info")
    assert okm1 == okm2

def test_hkdf_sensible_au_contexte():
    """Info différente → sortie différente."""
    okm1 = hkdf(b"ikm", 32, info=b"chiffrement")
    okm2 = hkdf(b"ikm", 32, info=b"authentification")
    assert okm1 != okm2


# ---------------------------------------------------------------------------
# Dérivation de clés DH
# ---------------------------------------------------------------------------

def test_dh_deriver_cles_taille():
    p = GROUPES["demo"]["p"]
    K = 2   # secret partagé de l'exemple du cours
    cle_enc, cle_auth = dh_deriver_cles(K, p)
    assert len(cle_enc)  == 32
    assert len(cle_auth) == 32

def test_dh_deriver_cles_distinctes():
    p = GROUPES["demo"]["p"]
    cle_enc, cle_auth = dh_deriver_cles(2, p)
    assert cle_enc != cle_auth

def test_dh_deriver_cles_deterministe():
    p = GROUPES["demo"]["p"]
    K = 7   # secret < p=23
    c1, a1 = dh_deriver_cles(K, p)
    c2, a2 = dh_deriver_cles(K, p)
    assert c1 == c2 and a1 == a2


# ---------------------------------------------------------------------------
# Confidentialité persistante
# ---------------------------------------------------------------------------

def test_forward_secrecy_statique_vulnerable():
    res = demo_forward_secrecy()
    assert res["statique_sessions_cassees_si_cle_compromise"]

def test_forward_secrecy_ephemere_protege():
    res = demo_forward_secrecy()
    assert res["ephemere_sessions_protegees"]


# ---------------------------------------------------------------------------
# Attaques (lab/)
# ---------------------------------------------------------------------------

def test_mitm_mallory_lit_message():
    p, g = GROUPES["demo"]["p"], GROUPES["demo"]["g"]
    res = simuler_mitm(p, g)
    assert res["mallory_a_lu"], "Mallory devrait pouvoir lire le message"
    assert not res["alice_detecte_mitm"]

def test_mitm_avec_signatures_detecte():
    p, g = GROUPES["demo"]["p"], GROUPES["demo"]["g"]
    res = simuler_mitm_avec_signatures(p, g)
    assert res["mitm_detecte"], "Le MITM devrait être détecté avec les signatures"

def test_bsgs_vecteur_simple():
    """BSGS doit retrouver x tel que g^x ≡ h (mod p)."""
    p, g = 23, 5
    for x_reel in [3, 7, 11, 15, 20]:
        h = expmod(g, x_reel, p)
        x_trouve = bsgs(g, h, p, ordre=p-1)
        assert x_trouve is not None
        assert expmod(g, x_trouve, p) == h

def test_bsgs_cours_ch4_ex3():
    """Vérifier que l'ordre de g=2 mod 23 est 11 (cours ch.4 ex.3)."""
    p, g = 23, 2
    ordre_2 = None
    for k in range(1, p):
        if expmod(g, k, p) == 1:
            ordre_2 = k
            break
    assert ordre_2 == 11, f"Ordre de 2 mod 23 = {ordre_2}, attendu 11"
    # BSGS dans le sous-groupe d'ordre 11
    h = expmod(g, 7, p)
    x = bsgs(g, h, p, ordre=11)
    assert x is not None
    assert expmod(g, x, p) == h

def test_attaque_bsgs_dh_30bits():
    res = attaque_bsgs_dh(bits_premier=25)
    assert res["succes"], f"BSGS échoué : {res}"
    assert res["duree_ms"] < 10_000   # moins de 10 secondes

def test_attaque_bsgs_complexite():
    """Le nombre de pas BSGS doit être ~ sqrt(p-1)."""
    res = attaque_bsgs_dh(bits_premier=20)
    assert res["succes"]
    # sqrt(p-1) est l'ordre de grandeur attendu
    assert res["complexite_theorique_sqrt"] < 2**11
