"""
Attaques pédagogiques sur RSA (module 3).
À n'utiliser que sur vos propres clés et paramètres de petite taille.
"""
from __future__ import annotations
import math
import time
from cryptolib.numtheory import expmod, inverse_mod, egcd, generate_prime


# ---------------------------------------------------------------------------
# Attaque 1 : Factorisation d'un module de 64 bits par Pollard-rho
# ---------------------------------------------------------------------------

def _pollard_rho(n: int) -> int:
    """
    Algorithme de Pollard-rho pour trouver un facteur non trivial de n.
    Complexité : O(n^(1/4)).
    Retourne un facteur p tel que 1 < p < n, ou n si échec.
    """
    if n % 2 == 0:
        return 2

    x = 2
    y = 2
    c = 1
    d = 1

    f = lambda t: (t * t + c) % n

    while d == 1:
        x = f(x)
        y = f(f(y))
        d = math.gcd(abs(x - y), n)

    return d if d != n else None

def factoriser_module(n: int) -> tuple[int, int] | None:
    """
    Factorise n = p*q en retrouvant p et q.
    Essaie plusieurs valeurs de c pour Pollard-rho.
    Retourne (p, q) ou None si échec.
    """
    for c in range(1, 50):
        x, y, d = 2, 2, 1
        f = lambda t: (t * t + c) % n
        while d == 1:
            x = f(x)
            y = f(f(y))
            d = math.gcd(abs(x - y), n)
        if 1 < d < n:
            p = d
            q = n // p
            if p * q == n:
                return (p, q)
    return None

def attaque_factorisation_64bits() -> dict:
    """
    Génère un module RSA de 64 bits, le factorise avec Pollard-rho
    et retrouve la clé privée.
    """
    from cryptolib.numtheory import generate_prime
    p, _ = generate_prime(32)
    q, _ = generate_prime(32)
    while q == p:
        q, _ = generate_prime(32)

    n   = p * q
    e   = 65537
    phi = (p - 1) * (q - 1)
    d   = inverse_mod(e, phi)

    debut = time.time()
    resultat = factoriser_module(n)
    duree = time.time() - debut

    if resultat is None:
        return {"succes": False, "n": n}

    p_trouve, q_trouve = resultat
    phi_trouve = (p_trouve - 1) * (q_trouve - 1)
    d_trouve   = inverse_mod(e, phi_trouve)

    return {
        "succes":    True,
        "n":         n,
        "p_reel":    p,
        "q_reel":    q,
        "p_trouve":  p_trouve,
        "q_trouve":  q_trouve,
        "d_reel":    d,
        "d_trouve":  d_trouve,
        "cles_egales": d == d_trouve,
        "duree_ms":  round(duree * 1000, 2),
    }


# ---------------------------------------------------------------------------
# Attaque 2 : Malléabilité du RSA sans padding
# ---------------------------------------------------------------------------

def attaque_malleabilite(n: int, e: int, C: int) -> dict:
    """
    Démontre la malléabilité du RSA textbook.
    Si C = M^e mod n, alors (2^e * C) mod n = (2M)^e mod n.
    Un oracle de déchiffrement sur le chiffré modifié donne 2M,
    d'où M = oracle(2^e * C) / 2.

    Ici on simule l'oracle avec la clé privée pour la démonstration.
    """
    # Facteur de malléabilité : k = 2
    k = 3
    k_e = expmod(k, e, n)
    C_prime = (k_e * C) % n    # = (k*M)^e mod n

    return {
        "C_original":  C,
        "C_modifie":   C_prime,
        "facteur":     k,
        "explication": (
            f"C' = {k}^e * C mod n = ({k}*M)^e mod n. "
            "Quiconque peut déchiffrer C' obtient k*M, puis M = k*M / k."
        ),
    }


# ---------------------------------------------------------------------------
# Attaque 3 : Petit message chiffré avec e=3 (racine cubique entière)
# ---------------------------------------------------------------------------

def _racine_cubique_entiere(n: int) -> int:
    """Calcule floor(n^(1/3)) par dichotomie."""
    if n < 0:
        raise ValueError("n doit être positif.")
    if n == 0:
        return 0
    # Estimation initiale
    r = int(round(n ** (1/3)))
    # Affiner
    for _ in range(100):
        r2 = (2 * r + n // (r * r)) // 3
        if r2 >= r:
            break
        r = r2
    # Chercher autour de r
    for delta in range(-2, 3):
        candidate = r + delta
        if candidate >= 0 and candidate ** 3 == n:
            return candidate
    return r

def attaque_petite_racine(C: int, e: int = 3) -> dict:
    """
    Si M^e < n (pas de réduction modulaire), on retrouve M
    par la racine e-ième entière de C = M^e.
    Fonctionne quand M est petit relativement à n.
    """
    if e == 3:
        M_retrouve = _racine_cubique_entiere(C)
        verif = M_retrouve ** 3 == C
    else:
        M_retrouve = int(round(C ** (1 / e)))
        verif = M_retrouve ** e == C

    return {
        "C":          C,
        "e":          e,
        "M_retrouve": M_retrouve,
        "correct":    verif,
        "explication": (
            f"Si M^{e} < n, alors C = M^{e} est un simple {e}e puissance entière. "
            "La racine entière suffit à retrouver M sans connaître la clé privée."
        ),
    }


# ---------------------------------------------------------------------------
# Attaque 4 : Deux modules partageant un facteur premier (PGCD)
# ---------------------------------------------------------------------------

def attaque_facteur_commun(n1: int, n2: int, e: int = 65537) -> dict:
    """
    Si deux modules RSA partagent un facteur premier p,
    pgcd(n1, n2) = p révèle immédiatement les deux clés privées.
    """
    p = math.gcd(n1, n2)
    if p == 1 or p == n1 or p == n2:
        return {"succes": False, "pgcd": p}

    q1 = n1 // p
    q2 = n2 // p

    phi1 = (p - 1) * (q1 - 1)
    phi2 = (p - 1) * (q2 - 1)

    try:
        d1 = inverse_mod(e, phi1)
        d2 = inverse_mod(e, phi2)
        succes = True
    except ValueError:
        d1 = d2 = None
        succes = False

    return {
        "succes":      succes,
        "p_commun":    p,
        "q1":          q1,
        "q2":          q2,
        "d1":          d1,
        "d2":          d2,
        "explication": (
            "pgcd(n1, n2) révèle le facteur commun p instantanément. "
            "Observé en 2012 sur des milliers de clés embarquées mal générées."
        ),
    }

def demo_facteur_commun() -> dict:
    """Génère deux modules partageant volontairement un facteur."""
    p, _  = generate_prime(32)
    q1, _ = generate_prime(32)
    q2, _ = generate_prime(32)
    while q2 == q1:
        q2, _ = generate_prime(32)

    n1 = p * q1
    n2 = p * q2
    return attaque_facteur_commun(n1, n2)


# ---------------------------------------------------------------------------
# Point d'entrée de démonstration
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 60)
    print("ATTAQUE 1 : Factorisation Pollard-rho (64 bits)")
    print("=" * 60)
    res = attaque_factorisation_64bits()
    if res["succes"]:
        print(f"  n = {res['n']}")
        print(f"  p trouvé    = {res['p_trouve']}  (réel : {res['p_reel']})")
        print(f"  q trouvé    = {res['q_trouve']}  (réel : {res['q_reel']})")
        print(f"  Clés égales : {res['cles_egales']}")
        print(f"  Durée       : {res['duree_ms']} ms")
    else:
        print("  Échec de la factorisation.")
    print()

    print("=" * 60)
    print("ATTAQUE 2 : Malléabilité RSA sans padding")
    print("=" * 60)
    # Petit exemple numérique
    p, q, e = 61, 53, 17
    n   = p * q       # 3233
    phi = (p-1)*(q-1)
    d   = inverse_mod(e, phi)
    M   = 42
    C   = expmod(M, e, n)
    res2 = attaque_malleabilite(n, e, C)
    C_prime = res2["C_modifie"]
    M_prime = expmod(C_prime, d, n)   # oracle simulé
    M_retrouve = M_prime // res2["facteur"]
    print(f"  M original    = {M}")
    print(f"  C original    = {C}")
    print(f"  C modifié     = {C_prime}")
    print(f"  M' déchiffré  = {M_prime}  (= {res2['facteur']}*M = {res2['facteur']*M})")
    print(f"  M retrouvé    = {M_retrouve}  ({'✓' if M_retrouve == M else '✗'})")
    print(f"  {res2['explication']}")
    print()

    print("=" * 60)
    print("ATTAQUE 3 : Petite racine cubique (e=3, sans padding)")
    print("=" * 60)
    M_petit = 12345
    C_cube  = M_petit ** 3     # pas de réduction mod n si M^3 < n
    res3    = attaque_petite_racine(C_cube, e=3)
    print(f"  M original  = {M_petit}")
    print(f"  C = M^3     = {C_cube}")
    print(f"  M retrouvé  = {res3['M_retrouve']}  ({'✓' if res3['correct'] else '✗'})")
    print(f"  {res3['explication']}")
    print()

    print("=" * 60)
    print("ATTAQUE 4 : Facteur premier commun (pgcd)")
    print("=" * 60)
    res4 = demo_facteur_commun()
    if res4["succes"]:
        print(f"  Facteur commun p = {res4['p_commun']}")
        print(f"  d1 retrouvé      = {res4['d1']}")
        print(f"  d2 retrouvé      = {res4['d2']}")
        print(f"  {res4['explication']}")
    print()
