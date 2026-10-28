"""
Module 2 : Arithmétique modulaire et nombres premiers
Implémenté sans bibliothèque cryptographique (entiers natifs Python uniquement).
"""
from __future__ import annotations
import os
import time


# ---------------------------------------------------------------------------
# PGCD et algorithme d'Euclide étendu
# ---------------------------------------------------------------------------

def pgcd(a: int, b: int) -> int:
    """PGCD par l'algorithme d'Euclide."""
    a, b = abs(a), abs(b)
    while b:
        a, b = b, a % b
    return a

def egcd(a: int, b: int) -> tuple[int, int, int]:
    """
    Algorithme d'Euclide étendu.
    Retourne (g, u, v) tels que a*u + b*v = g = pgcd(a, b).
    """
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t
    return old_r, old_s, old_t   # (g, u, v)


# ---------------------------------------------------------------------------
# Inverse modulaire et exponentiation modulaire
# ---------------------------------------------------------------------------

def inverse_mod(a: int, n: int) -> int:
    """
    Inverse de a modulo n (algorithme d'Euclide étendu).
    Lève ValueError si pgcd(a, n) != 1.
    """
    g, u, _ = egcd(a % n, n)
    if g != 1:
        raise ValueError(f"{a} n'est pas inversible modulo {n} (pgcd={g}).")
    return u % n

def expmod(a: int, e: int, n: int) -> int:
    """
    Exponentiation modulaire par la méthode square-and-multiply.
    Calcule a^e mod n sans utiliser pow() à trois arguments.
    """
    if n == 1:
        return 0
    resultat = 1
    a = a % n
    while e > 0:
        if e & 1:                       # bit de poids faible à 1
            resultat = (resultat * a) % n
        a = (a * a) % n
        e >>= 1
    return resultat


# ---------------------------------------------------------------------------
# Théorème des restes chinois (CRT)
# ---------------------------------------------------------------------------

def crt(restes: list[int], moduli: list[int]) -> int:
    """
    Théorème des restes chinois pour k congruences.
    Résout x ≡ restes[i] (mod moduli[i]) pour tout i.
    Les moduli doivent être deux à deux premiers entre eux.
    Retourne l'unique solution modulo M = prod(moduli).
    """
    M = 1
    for m in moduli:
        M *= m

    x = 0
    for a_i, m_i in zip(restes, moduli):
        M_i = M // m_i
        inv = inverse_mod(M_i, m_i)
        x += a_i * M_i * inv

    return x % M


# ---------------------------------------------------------------------------
# Tests de primalité
# ---------------------------------------------------------------------------

def fermat_probable_premier(n: int, a: int) -> bool:
    """
    Test de primalité de Fermat pour la base a.
    Retourne True si n est probablement premier, False s'il est composé.
    Attention : les nombres de Carmichael trompent ce test.
    """
    if n < 2:
        return False
    return expmod(a, n - 1, n) == 1

def miller_rabin(n: int, k: int = 40) -> bool:
    """
    Test de Miller-Rabin probabiliste avec k bases aléatoires.
    Probabilité d'erreur ≤ 4^(-k).
    Retourne True si n est probablement premier, False s'il est composé.
    """
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    # Écrire n-1 = 2^s * d avec d impair
    s, d = 0, n - 1
    while d % 2 == 0:
        s += 1
        d //= 2

    for _ in range(k):
        a = 2 + int.from_bytes(os.urandom(4), "big") % (n - 3)
        x = expmod(a, d, n)

        if x == 1 or x == n - 1:
            continue

        for _ in range(s - 1):
            x = (x * x) % n
            if x == n - 1:
                break
        else:
            return False   # n est composé

    return True   # probablement premier


# ---------------------------------------------------------------------------
# Génération de nombres premiers
# ---------------------------------------------------------------------------

# Petits premiers pour le crible rapide avant Miller-Rabin
_PETITS_PREMIERS = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47,
    53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107,
    109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173,
]

def _crible_rapide(n: int) -> bool:
    """Élimine les candidats divisibles par un petit premier."""
    for p in _PETITS_PREMIERS:
        if n == p:
            return True
        if n % p == 0:
            return False
    return True

def generate_prime(bits: int, k: int = 40) -> tuple[int, int]:
    """
    Génère un nombre premier aléatoire de `bits` bits.
    Retourne (premier, nb_candidats_testes).
    """
    candidats = 0
    while True:
        # Nombre aléatoire de `bits` bits, impair, bit de poids fort à 1
        n = int.from_bytes(os.urandom(bits // 8), "big")
        n |= (1 << (bits - 1))   # bit haut
        n |= 1                    # impair
        candidats += 1
        if _crible_rapide(n) and miller_rabin(n, k):
            return n, candidats


# ---------------------------------------------------------------------------
# Indicatrice d'Euler (pour de petits n)
# ---------------------------------------------------------------------------

def _factorisation(n: int) -> dict[int, int]:
    """Factorisation naïve. Retourne {p: exposant}."""
    facteurs: dict[int, int] = {}
    d = 2
    while d * d <= n:
        while n % d == 0:
            facteurs[d] = facteurs.get(d, 0) + 1
            n //= d
        d += 1
    if n > 1:
        facteurs[n] = facteurs.get(n, 0) + 1
    return facteurs

def euler_phi(n: int) -> int:
    """
    Calcule l'indicatrice d'Euler φ(n) par factorisation naïve.
    Formule : φ(n) = n * prod(1 - 1/p) pour chaque facteur premier p.
    """
    if n <= 0:
        raise ValueError("n doit être un entier positif.")
    resultat = n
    for p in _factorisation(n):
        resultat -= resultat // p
    return resultat


# ---------------------------------------------------------------------------
# Point d'entrée de démonstration
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # PGCD et Euclide étendu
    print("=== PGCD et Euclide étendu ===")
    a, b = 240, 46
    g = pgcd(a, b)
    g2, u, v = egcd(a, b)
    print(f"pgcd({a}, {b}) = {g}")
    print(f"  {a}*({u}) + {b}*({v}) = {a*u + b*v}  (vérifié : {a*u + b*v == g2})")
    print()

    # Inverse modulaire
    print("=== Inverse modulaire ===")
    print(f"  17^-1 mod 3120 = {inverse_mod(17, 3120)}")
    print(f"  7^-1  mod 26   = {inverse_mod(7, 26)}")
    print()

    # Exponentiation modulaire
    print("=== Exponentiation modulaire (square-and-multiply) ===")
    print(f"  3^13 mod 7  = {expmod(3, 13, 7)}  (attendu 3)")
    print(f"  7^2026 mod 13 = {expmod(7, 2026, 13)}  (attendu 4, cours ch.2)")
    print(f"  Vérif pow() : {pow(3, 13, 7)}")
    print()

    # CRT
    print("=== Théorème des restes chinois ===")
    x = crt([2, 3, 2], [3, 5, 7])
    print(f"  x ≡ 2(mod 3), 3(mod 5), 2(mod 7) → x = {x}  (attendu 23)")
    print()

    # Miller-Rabin vs nombres de Carmichael
    print("=== Miller-Rabin vs nombres de Carmichael ===")
    for n in [561, 1105, 1729]:
        fermat_ok = fermat_probable_premier(n, 2)
        mr_ok = miller_rabin(n, 40)
        print(f"  n={n} : Fermat(base 2)={fermat_ok}, Miller-Rabin={mr_ok}")
    print()

    # Génération de premiers
    print("=== Génération de nombres premiers ===")
    for bits in [64, 128, 512]:
        debut = time.time()
        p, nb = generate_prime(bits)
        duree = time.time() - debut
        import math
        theorique = math.log(2 ** bits) / 2
        print(f"  {bits} bits : {nb} candidats testés "
              f"(théorique ~{theorique:.0f}), {duree*1000:.1f} ms")
    print()

    # Indicatrice d'Euler
    print("=== Indicatrice d'Euler ===")
    for n in [12, 35, 36, 77, 101]:
        print(f"  φ({n}) = {euler_phi(n)}")
    print()

    # Vérification du théorème d'Euler
    print("=== Vérification théorème d'Euler : a^φ(n) ≡ 1 (mod n) ===")
    n, a = 35, 4
    phi = euler_phi(n)
    print(f"  {a}^φ({n}) = {a}^{phi} mod {n} = {expmod(a, phi, n)}  (attendu 1)")
