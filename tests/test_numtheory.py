"""
Tests unitaires pour cryptolib/numtheory.py
Vecteurs : exemples du cours, RFC 3526, NIST.
"""
from __future__ import annotations
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import math
import pytest
from cryptolib.numtheory import (
    pgcd, egcd,
    inverse_mod, expmod,
    crt,
    fermat_probable_premier, miller_rabin,
    generate_prime,
    euler_phi,
)


# ---------------------------------------------------------------------------
# PGCD
# ---------------------------------------------------------------------------

def test_pgcd_exemples_cours():
    assert pgcd(240, 46) == 2
    assert pgcd(1071, 462) == 21

def test_pgcd_copremiers():
    assert pgcd(17, 3120) == 1

def test_pgcd_un_nul():
    assert pgcd(0, 5) == 5
    assert pgcd(7, 0) == 7

def test_pgcd_commutatif():
    assert pgcd(48, 18) == pgcd(18, 48)

def test_pgcd_meme_valeur():
    assert pgcd(12, 12) == 12


# ---------------------------------------------------------------------------
# Euclide étendu
# ---------------------------------------------------------------------------

def test_egcd_bezout_240_46():
    g, u, v = egcd(240, 46)
    assert g == 2
    assert 240 * u + 46 * v == g

def test_egcd_bezout_1071_462():
    """Vecteur du cours : pgcd(1071, 462) = 21."""
    g, u, v = egcd(1071, 462)
    assert g == 21
    assert 1071 * u + 462 * v == 21

def test_egcd_copremiers():
    g, u, v = egcd(17, 3120)
    assert g == 1
    assert 17 * u + 3120 * v == 1


# ---------------------------------------------------------------------------
# Inverse modulaire
# ---------------------------------------------------------------------------

def test_inverse_mod_17_3120():
    """Vecteur du cours chapitre 2 exercice 2."""
    assert inverse_mod(17, 3120) == 2753

def test_inverse_mod_7_26():
    """Vecteur du cours : 7^-1 mod 26 = 15."""
    assert inverse_mod(7, 26) == 15

def test_inverse_mod_non_inversible():
    with pytest.raises(ValueError):
        inverse_mod(4, 6)   # pgcd(4,6)=2 ≠ 1

def test_inverse_mod_coherence():
    """a * a^-1 ≡ 1 (mod n)."""
    for a, n in [(3, 11), (17, 3120), (65537, 2**16 + 1)]:
        if math.gcd(a, n) == 1:
            inv = inverse_mod(a, n)
            assert (a * inv) % n == 1


# ---------------------------------------------------------------------------
# Exponentiation modulaire
# ---------------------------------------------------------------------------

def test_expmod_exemple_cours():
    """3^13 mod 7 = 3 (cours chapitre 2)."""
    assert expmod(3, 13, 7) == 3

def test_expmod_7_2026_mod13():
    """7^2026 mod 13 = 4 (réponses exercices cours)."""
    assert expmod(7, 2026, 13) == 4

def test_expmod_5_23_mod11():
    """5^23 mod 11 = 4 (réponses exercices cours)."""
    assert expmod(5, 23, 11) == 4

def test_expmod_correspond_pow():
    """Vérification contre pow() natif Python sur plusieurs cas."""
    cas = [(3, 13, 7), (17, 2753, 3233), (65537, 1000003, 2**61 - 1)]
    for a, e, n in cas:
        assert expmod(a, e, n) == pow(a, e, n)

def test_expmod_exposant_nul():
    assert expmod(5, 0, 13) == 1

def test_expmod_base_nulle():
    assert expmod(0, 100, 7) == 0

def test_expmod_grand_exposant():
    """Test sur des valeurs de taille RSA (performance)."""
    import time
    a, e, n = 65537, 2**2048 - 1, 2**2048 - 159
    debut = time.time()
    r1 = expmod(a, e, n)
    r2 = pow(a, e, n)
    duree = time.time() - debut
    assert r1 == r2
    assert duree < 5.0, f"Trop lent : {duree:.2f}s"


# ---------------------------------------------------------------------------
# CRT
# ---------------------------------------------------------------------------

def test_crt_exemple_cours():
    """x ≡ 2(3), 3(5), 2(7) → 23 (cours + Sun Zi)."""
    assert crt([2, 3, 2], [3, 5, 7]) == 23

def test_crt_exemple_exercice():
    """x ≡ 1(4), 2(5), 3(7) → 17 (réponses exercices cours)."""
    assert crt([1, 2, 3], [4, 5, 7]) == 17

def test_crt_deux_congruences():
    x = crt([3, 4], [5, 7])
    assert x % 5 == 3
    assert x % 7 == 4

def test_crt_solution_unique_modulo_M():
    restes = [2, 3, 2]
    moduli = [3, 5, 7]
    x = crt(restes, moduli)
    M = 3 * 5 * 7
    assert 0 <= x < M
    for a_i, m_i in zip(restes, moduli):
        assert x % m_i == a_i


# ---------------------------------------------------------------------------
# Tests de primalité
# ---------------------------------------------------------------------------

PREMIERS_CONNUS = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 97, 101, 1009,
                   7919, 15485863, 2**31 - 1]   # premier de Mersenne

COMPOSES_CONNUS = [4, 6, 9, 15, 100, 561, 1105, 1729]   # dont Carmichael

def test_miller_rabin_premiers():
    for p in PREMIERS_CONNUS:
        assert miller_rabin(p), f"{p} devrait être premier"

def test_miller_rabin_composes():
    for n in COMPOSES_CONNUS:
        assert not miller_rabin(n), f"{n} devrait être composé"

def test_miller_rabin_nombres_carmichael():
    """Miller-Rabin doit rejeter les nombres de Carmichael (contrairement à Fermat)."""
    for n in [561, 1105, 1729]:
        assert not miller_rabin(n, k=40), (
            f"Miller-Rabin a tort sur le nombre de Carmichael {n}"
        )

def test_fermat_accepte_carmichael():
    """Le test de Fermat (base 2) accepte à tort 561."""
    assert fermat_probable_premier(561, 2), "Fermat(561, base=2) devrait retourner True"

def test_miller_rabin_petit_premier():
    assert miller_rabin(2)
    assert miller_rabin(3)
    assert not miller_rabin(1)
    assert not miller_rabin(0)


# ---------------------------------------------------------------------------
# Génération de nombres premiers
# ---------------------------------------------------------------------------

def test_generate_prime_est_premier():
    for bits in [64, 128]:
        p, nb = generate_prime(bits)
        assert miller_rabin(p, 40), f"{p} devrait être premier"

def test_generate_prime_bonne_taille():
    for bits in [64, 128, 256]:
        p, _ = generate_prime(bits)
        assert p.bit_length() == bits, (
            f"Attendu {bits} bits, obtenu {p.bit_length()}"
        )

def test_generate_prime_deux_distincts():
    """Deux appels doivent retourner des premiers distincts (quasi-sûr)."""
    p1, _ = generate_prime(128)
    p2, _ = generate_prime(128)
    assert p1 != p2

def test_generate_prime_nb_candidats_ordre():
    """
    Le nombre de candidats testés doit être dans l'ordre de ln(2^bits)/2.
    On accepte une large marge (0.1x–20x) à cause de la variance.
    """
    bits = 128
    theorique = math.log(2 ** bits) / 2
    totaux = []
    for _ in range(5):
        _, nb = generate_prime(bits)
        totaux.append(nb)
    moyenne = sum(totaux) / len(totaux)
    assert theorique * 0.1 <= moyenne <= theorique * 20, (
        f"Moyenne {moyenne:.1f} hors de l'intervalle autour de {theorique:.1f}"
    )


# ---------------------------------------------------------------------------
# Indicatrice d'Euler
# ---------------------------------------------------------------------------

def test_euler_phi_valeurs_cours():
    assert euler_phi(12) == 4
    assert euler_phi(35) == 24
    assert euler_phi(36) == 12
    assert euler_phi(77) == 60
    assert euler_phi(101) == 100   # 101 est premier

def test_euler_phi_premier():
    """Pour p premier : φ(p) = p-1."""
    for p in [2, 3, 5, 7, 11, 13, 97]:
        assert euler_phi(p) == p - 1

def test_euler_phi_puissance_de_premier():
    """φ(p^k) = p^k - p^(k-1)."""
    assert euler_phi(8) == 4    # 2^3 - 2^2
    assert euler_phi(9) == 6    # 3^2 - 3^1
    assert euler_phi(25) == 20  # 5^2 - 5^1

def test_euler_theoreme():
    """a^φ(n) ≡ 1 (mod n) pour pgcd(a,n) = 1."""
    cas = [(4, 35), (3, 10), (7, 36)]
    for a, n in cas:
        phi = euler_phi(n)
        assert expmod(a, phi, n) == 1, (
            f"{a}^φ({n}) mod {n} ≠ 1"
        )

def test_euler_phi_n1():
    assert euler_phi(1) == 1

def test_euler_phi_invalide():
    with pytest.raises(ValueError):
        euler_phi(0)
