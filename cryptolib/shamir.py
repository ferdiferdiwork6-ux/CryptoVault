"""
Bonus : Partage de secret de Shamir (k parmi n).
Implémenté sans bibliothèque cryptographique (arithmétique sur GF(p)).

Principe :
  - On choisit un polynôme aléatoire f(x) de degré k-1 tel que f(0) = secret.
  - On distribue n parts (xi, f(xi)) pour xi = 1..n.
  - N'importe quel sous-ensemble de k parts permet de reconstruire f(0) par
    interpolation de Lagrange.
  - Moins de k parts ne donnent aucune information sur le secret (sécurité
    parfaite si p est premier et grand).

Usage typique : sauvegarder la clé privée de l'AC racine entre n administrateurs,
avec un seuil k pour la reconstituer.
"""
from __future__ import annotations
import os
from cryptolib.numtheory import inverse_mod
from cryptolib.prng import HMAC_DRBG

# Premier de Mersenne 2^521 - 1 (sécurité 521 bits, largement suffisant pour
# protéger des secrets de 256 bits)
_P = 2**521 - 1

_drbg = HMAC_DRBG()


def _alea_mod_p() -> int:
    """Génère un entier aléatoire dans [1, p-1]."""
    nb = (_P.bit_length() + 7) // 8
    while True:
        v = int.from_bytes(_drbg.generer_octets(nb), "big") % _P
        if v > 0:
            return v


def partager_secret(
    secret: int,
    k: int,
    n: int,
    p: int = _P,
) -> list[tuple[int, int]]:
    """
    Partage `secret` en n parts avec seuil k (k parmi n).

    Paramètres
    ----------
    secret : entier dans [0, p-1] à partager.
    k      : nombre minimum de parts pour reconstruire (seuil).
    n      : nombre total de parts à distribuer.
    p      : premier définissant GF(p). Doit être > secret et > n.

    Retourne
    --------
    Liste de n tuples (xi, yi) = (i, f(i)) pour i = 1..n.
    """
    if k < 2:
        raise ValueError("Le seuil k doit être >= 2.")
    if n < k:
        raise ValueError("n doit être >= k.")
    if secret >= p:
        raise ValueError("Le secret doit être < p.")

    # Coefficients du polynôme : a[0] = secret, a[1..k-1] aléatoires dans GF(p)
    coefficients = [secret] + [_alea_mod_p() % p for _ in range(k - 1)]

    def evaluer(x: int) -> int:
        """Évalue le polynôme en x modulo p (schéma de Horner)."""
        valeur = 0
        for coeff in reversed(coefficients):
            valeur = (valeur * x + coeff) % p
        return valeur

    return [(i, evaluer(i)) for i in range(1, n + 1)]


def reconstruire_secret(
    parts: list[tuple[int, int]],
    p: int = _P,
) -> int:
    """
    Reconstruit le secret f(0) à partir d'au moins k parts par
    interpolation de Lagrange sur GF(p).

    Paramètres
    ----------
    parts : liste d'au moins k tuples (xi, yi).
    p     : même premier que lors du partage.

    Retourne
    --------
    Le secret f(0) modulo p.
    """
    if len(parts) < 2:
        raise ValueError("Il faut au moins 2 parts pour reconstruire.")

    secret = 0
    for i, (xi, yi) in enumerate(parts):
        # Calcul du coefficient de Lagrange L_i(0)
        numerateur   = 1
        denominateur = 1
        for j, (xj, _) in enumerate(parts):
            if i == j:
                continue
            # L_i(0) = prod_{j≠i} (0 - xj) / (xi - xj)
            numerateur   = (numerateur   * (-xj)) % p
            denominateur = (denominateur * (xi - xj)) % p
        lagrange = numerateur * inverse_mod(denominateur, p) % p
        secret = (secret + yi * lagrange) % p

    return secret


def partager_cle_bytes(
    cle: bytes,
    k: int,
    n: int,
    p: int = _P,
) -> list[tuple[int, int]]:
    """
    Partage une clé bytes (ex. clé privée AES-256 ou RSA sérialisée).
    La clé est convertie en entier, partagée, puis les parts sont retournées.
    """
    secret_int = int.from_bytes(cle, "big")
    if secret_int >= p:
        raise ValueError(f"La clé est trop grande pour ce corps GF(p). "
                         f"Utilisez un p plus grand.")
    return partager_secret(secret_int, k, n, p)


def reconstruire_cle_bytes(
    parts: list[tuple[int, int]],
    longueur_octets: int,
    p: int = _P,
) -> bytes:
    """Reconstruit une clé bytes depuis ses parts de Shamir."""
    secret_int = reconstruire_secret(parts, p)
    return secret_int.to_bytes(longueur_octets, "big")


# ---------------------------------------------------------------------------
# Démonstration
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=== Partage de secret de Shamir (k=3 parmi n=5) ===")

    # Clé AES-256 simulant la clé de l'AC racine
    cle_racine = os.urandom(32)
    print(f"  Clé originale  : {cle_racine.hex()}")

    parts = partager_cle_bytes(cle_racine, k=3, n=5)
    print(f"  {len(parts)} parts distribuées aux administrateurs")

    # Reconstruction avec exactement k=3 parts (les admins 1, 3, 5)
    parts_utilisees = [parts[0], parts[2], parts[4]]
    cle_reconstruite = reconstruire_cle_bytes(parts_utilisees, 32)
    print(f"  Reconstruite   : {cle_reconstruite.hex()}")
    print(f"  Identiques     : {cle_racine == cle_reconstruite}")

    # Vérifier qu'avec k-1=2 parts on ne peut pas reconstruire
    parts_insuffisantes = [parts[0], parts[1]]
    faux_secret = reconstruire_cle_bytes(parts_insuffisantes, 32)
    print(f"\n  Avec seulement 2 parts (< k=3) :")
    print(f"  Valeur obtenue : {faux_secret.hex()}")
    print(f"  Correspond     : {cle_racine == faux_secret}  (doit être False)")
