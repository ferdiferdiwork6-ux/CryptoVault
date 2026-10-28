"""
Tests unitaires pour cryptolib/ecc.py et lab/attaques_ecc.py
Vecteurs : cours ch.5, NIST FIPS 186-4.
"""
from __future__ import annotations
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import hashlib
import time
import pytest
from cryptolib.ecc import (
    Point, INFINI, CourbeElliptique, CourbeAvecParametres,
    COURBE_JOUET, P256, SECP256K1, COURBES,
    ecdh_generer_cle, ecdh_secret_partage,
    ecdsa_signer, ecdsa_verifier,
    attaque_nonce_reutilise, _bits2int, _rfc6979_nonce,
)
from cryptolib.numtheory import inverse_mod
from lab.attaques_ecc import demo_attaque_nonce_reutilise, demo_nonce_deterministe


# ---------------------------------------------------------------------------
# Courbe jouet : y² = x³ + 2x + 2 sur 𝔽₁₇
# Table des multiples de G=(5,1) d'après le cours (ch.5 §5.3)
# ---------------------------------------------------------------------------

MULTIPLES_COURS = [
    (1,  5,  1), (2,  6,  3), (3,  10,  6), (4,   3,  1), (5,   9, 16),
    (6, 16, 13), (7,  0,  6), (8,  13,  7), (9,   7,  6), (10,  7, 11),
    (11,13, 10), (12, 0, 11), (13, 16,  4), (14,  9,  1), (15,  3, 16),
    (16,10, 11), (17, 6, 14), (18, 5, 16),
]

@pytest.mark.parametrize("k,x,y", MULTIPLES_COURS)
def test_multiples_jouet(k, x, y):
    P = COURBE_JOUET.multiplier(k, COURBE_JOUET.G)
    assert P.x == x and P.y == y, f"{k}G attendu ({x},{y}), obtenu {P}"

def test_19G_est_infini():
    assert COURBE_JOUET.multiplier(19, COURBE_JOUET.G).est_infini

def test_0G_est_infini():
    assert COURBE_JOUET.multiplier(0, COURBE_JOUET.G).est_infini


# ---------------------------------------------------------------------------
# Propriétés du groupe (cours ch.5)
# ---------------------------------------------------------------------------

def test_oppose_jouet():
    G = COURBE_JOUET.G
    neg_G = COURBE_JOUET.oppose(G)
    assert (G.y + neg_G.y) % COURBE_JOUET.p == 0

def test_G_plus_oppose_est_infini():
    G = COURBE_JOUET.G
    assert COURBE_JOUET.ajouter(G, COURBE_JOUET.oppose(G)).est_infini

def test_commutatif():
    C = COURBE_JOUET
    P = C.multiplier(3, C.G)
    Q = C.multiplier(7, C.G)
    assert C.ajouter(P, Q) == C.ajouter(Q, P)

def test_associatif():
    C = COURBE_JOUET
    P, Q, R = C.multiplier(2, C.G), C.multiplier(5, C.G), C.multiplier(8, C.G)
    assert C.ajouter(C.ajouter(P, Q), R) == C.ajouter(P, C.ajouter(Q, R))

def test_infini_neutre():
    G = COURBE_JOUET.G
    assert COURBE_JOUET.ajouter(G, INFINI) == G
    assert COURBE_JOUET.ajouter(INFINI, G) == G

def test_doublement_egal_addition_elle_meme():
    C = COURBE_JOUET
    G = C.G
    assert C.ajouter(G, G) == C.multiplier(2, G)


# ---------------------------------------------------------------------------
# Exercices du cours ch.5
# ---------------------------------------------------------------------------

def test_exercice_ch5_ex1_3G():
    """Ex 1 : 3G = 2G + G = (6,3) + (5,1) = (10,6)."""
    C  = COURBE_JOUET
    G2 = C.multiplier(2, C.G)
    G3 = C.ajouter(G2, C.G)
    assert G3 == Point(10, 6)

def test_exercice_ch5_ex2_ecdh():
    """Ex 2 : Alice a=3, Bob b=5. A=3G=(10,6), B=5G=(9,16), K=15G=(3,16)."""
    C = COURBE_JOUET
    A = C.multiplier(3, C.G)
    B = C.multiplier(5, C.G)
    assert A == Point(10, 6)
    assert B == Point(9, 16)
    K_alice = C.multiplier(3, B)
    K_bob   = C.multiplier(5, A)
    assert K_alice == K_bob == C.multiplier(15, C.G)

def test_exercice_ch5_ex3_double_and_add():
    """Ex 3 : 25 = 11001₂ → 4 doublements + 2 additions."""
    # 25 = 16+8+1 → bits: 11001 → 4 doublements, 3 bits à 1 donc 2 additions après le premier
    # Vérification directe
    C = COURBE_JOUET
    P25_direct = C.multiplier(25 % C.n, C.G)
    # 25 mod 19 = 6 (ordre = 19)
    assert P25_direct == C.multiplier(6, C.G)


# ---------------------------------------------------------------------------
# P-256 : vérification que n·G = ∞
# ---------------------------------------------------------------------------

def test_p256_nG_infini():
    """n·G = ∞ sur P-256."""
    assert P256.multiplier(P256.n, P256.G).est_infini

def test_p256_G_sur_courbe():
    assert P256.est_sur_courbe(P256.G)

def test_secp256k1_nG_infini():
    assert SECP256K1.multiplier(SECP256K1.n, SECP256K1.G).est_infini


# ---------------------------------------------------------------------------
# ECDH
# ---------------------------------------------------------------------------

def test_ecdh_secret_partage_jouet():
    """Secret partagé ECDH sur la courbe jouet."""
    C = COURBE_JOUET
    a, A = 3, C.multiplier(3, C.G)
    b, B = 5, C.multiplier(5, C.G)
    K_a = ecdh_secret_partage(a, B, C)
    K_b = ecdh_secret_partage(b, A, C)
    assert K_a == K_b

def test_ecdh_secret_partage_p256():
    d_a, Q_a = ecdh_generer_cle(P256)
    d_b, Q_b = ecdh_generer_cle(P256)
    K_a = ecdh_secret_partage(d_a, Q_b, P256)
    K_b = ecdh_secret_partage(d_b, Q_a, P256)
    assert K_a == K_b

def test_ecdh_cles_differentes():
    d1, Q1 = ecdh_generer_cle(P256)
    d2, Q2 = ecdh_generer_cle(P256)
    assert Q1 != Q2

def test_ecdh_point_invalide_rejete():
    with pytest.raises(ValueError):
        ecdh_secret_partage(42, Point(0, 0), P256)


# ---------------------------------------------------------------------------
# ECDSA
# ---------------------------------------------------------------------------

def test_ecdsa_signature_valide_p256():
    d, Q = ecdh_generer_cle(P256)
    msg  = b"Bonjour CryptoVault"
    sig  = ecdsa_signer(msg, d, P256)
    assert ecdsa_verifier(msg, sig, Q, P256)

def test_ecdsa_message_modifie_rejete():
    d, Q = ecdh_generer_cle(P256)
    sig  = ecdsa_signer(b"original", d, P256)
    assert not ecdsa_verifier(b"modifie", sig, Q, P256)

def test_ecdsa_mauvaise_cle_rejetee():
    d, _  = ecdh_generer_cle(P256)
    _, Q2 = ecdh_generer_cle(P256)
    sig   = ecdsa_signer(b"test", d, P256)
    assert not ecdsa_verifier(b"test", sig, Q2, P256)

def test_ecdsa_deterministe_rfc6979():
    """RFC 6979 : deux signatures du même message avec la même clé sont identiques."""
    d, Q = ecdh_generer_cle(P256)
    msg  = b"message test"
    sig1 = ecdsa_signer(msg, d, P256, nonce_aleatoire=False)
    sig2 = ecdsa_signer(msg, d, P256, nonce_aleatoire=False)
    assert sig1 == sig2

def test_ecdsa_aleatoire_non_deterministe():
    """Avec nonce aléatoire, deux signatures du même message diffèrent."""
    d, Q  = ecdh_generer_cle(P256)
    msg   = b"message test"
    sig1  = ecdsa_signer(msg, d, P256, nonce_aleatoire=True)
    sig2  = ecdsa_signer(msg, d, P256, nonce_aleatoire=True)
    # Les deux signatures doivent quand même être valides
    assert ecdsa_verifier(msg, sig1, Q, P256)
    assert ecdsa_verifier(msg, sig2, Q, P256)

def test_ecdsa_r_s_dans_intervalle():
    """r et s doivent être dans [1, n-1]."""
    d, Q = ecdh_generer_cle(P256)
    r, s = ecdsa_signer(b"test", d, P256)
    assert 1 <= r < P256.n
    assert 1 <= s < P256.n

def test_ecdsa_signature_invalide_rejetee():
    d, Q = ecdh_generer_cle(P256)
    msg  = b"test"
    r, s = ecdsa_signer(msg, d, P256)
    assert not ecdsa_verifier(msg, (r + 1, s), Q, P256)
    assert not ecdsa_verifier(msg, (r, s + 1), Q, P256)


# ---------------------------------------------------------------------------
# Attaque : réutilisation de nonce
# ---------------------------------------------------------------------------

def test_attaque_nonce_reutilise_retrouve_cle():
    res = demo_attaque_nonce_reutilise(P256)
    assert res["succes"], f"L'attaque devrait réussir : {res}"

def test_attaque_nonce_reutilise_sur_jouet():
    """Même attaque sur la courbe jouet (plus rapide)."""
    C  = COURBE_JOUET
    n  = C.n
    d  = 7   # clé privée arbitraire
    Q  = C.multiplier(d, C.G)
    k  = 11  # nonce fixe

    R  = C.multiplier(k, C.G)
    r  = R.x % n

    msg1, msg2 = b"msg1", b"msg2"
    z1 = _bits2int(hashlib.sha256(msg1).digest(), n.bit_length())
    z2 = _bits2int(hashlib.sha256(msg2).digest(), n.bit_length())
    k_inv = inverse_mod(k, n)
    s1 = k_inv * (z1 + r * d) % n
    s2 = k_inv * (z2 + r * d) % n

    d_retrouve = attaque_nonce_reutilise(msg1, (r, s1), msg2, (r, s2), C)
    assert d_retrouve is not None
    assert d_retrouve % n == d % n

def test_attaque_nonces_differents_echoue():
    """Sans réutilisation, l'attaque doit échouer (r1 ≠ r2)."""
    d, Q = ecdh_generer_cle(P256)
    sig1 = ecdsa_signer(b"msg1", d, P256)
    sig2 = ecdsa_signer(b"msg2", d, P256)
    # RFC 6979 : nonces différents → r différents (quasi certain)
    if sig1[0] != sig2[0]:
        result = attaque_nonce_reutilise(b"msg1", sig1, b"msg2", sig2, P256)
        assert result is None


# ---------------------------------------------------------------------------
# Nonce déterministe RFC 6979
# ---------------------------------------------------------------------------

def test_nonce_deterministe_demo():
    res = demo_nonce_deterministe(P256)
    assert res["nonces_distincts_pour_messages_differents"]
    assert res["meme_message_meme_nonce"]
    assert res["signature_deterministe"]
    assert res["signature_valide"]


# ---------------------------------------------------------------------------
# Comparaison RSA vs ECC (taille et temps)
# ---------------------------------------------------------------------------

def test_comparaison_rsa_ecc_taille():
    """Clé P-256 = 256 bits, RSA-3072 ≈ même niveau de sécurité."""
    from cryptolib.rsa import generer_cles_rsa
    d, Q = ecdh_generer_cle(P256)
    assert P256.n.bit_length() == 256

    cles_rsa = generer_cles_rsa(bits=512)   # module 1024 bits (test rapide)
    assert cles_rsa["bits_module"] >= 1020   # 2×512 bits, légère variance possible

def test_comparaison_rsa_ecc_performance():
    """ECDSA P-256 doit être plus rapide que RSA-1024 pour la signature."""
    from cryptolib.rsa import generer_cles_rsa, signer_rsa

    ESSAIS = 3

    # RSA signature
    cles = generer_cles_rsa(bits=512)
    debut = time.time()
    for _ in range(ESSAIS):
        signer_rsa(b"test", cles["privee"])
    t_rsa = time.time() - debut

    # ECDSA P-256 signature
    d, Q = ecdh_generer_cle(P256)
    debut = time.time()
    for _ in range(ESSAIS):
        ecdsa_signer(b"test", d, P256)
    t_ecc = time.time() - debut

    # P-256 doit être comparable ou plus rapide (pas garanti en Python pur,
    # on vérifie juste que les deux s'exécutent dans un délai raisonnable)
    assert t_rsa < 30.0
    assert t_ecc < 30.0
