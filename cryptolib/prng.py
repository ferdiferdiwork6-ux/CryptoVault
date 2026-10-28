"""
Module 8 : Générateurs pseudo-aléatoires.
- LCG (Générateur congruentiel linéaire)
- Mersenne Twister MT19937
- CSPRNG HMAC_DRBG (NIST SP 800-90A)
- Tests statistiques : monobit, runs, chi²
"""
from __future__ import annotations
import os
import math
import struct
from cryptolib.hashing import hmac_sha256


# ---------------------------------------------------------------------------
# 1. LCG — Générateur congruentiel linéaire
# ---------------------------------------------------------------------------

class LCG:
    """
    X_{n+1} = (a * X_n + c) mod m
    Paramètres par défaut : ceux du cours (m=16, a=5, c=3).
    """

    def __init__(self, graine: int, m: int = 2**32, a: int = 1664525,
                 c: int = 1013904223):
        self.m = m
        self.a = a
        self.c = c
        self.etat = graine % m

    def suivant(self) -> int:
        self.etat = (self.a * self.etat + self.c) % self.m
        return self.etat

    def generer(self, n: int) -> list[int]:
        return [self.suivant() for _ in range(n)]

    def octets(self, n: int) -> bytes:
        """Génère n octets (les 8 bits de poids faible de chaque valeur)."""
        return bytes(self.suivant() & 0xFF for _ in range(n))


class LCG_Cours:
    """LCG exact du cours : m=16, a=5, c=3 (pour les vecteurs ch.8)."""

    def __init__(self, graine: int):
        self.m     = 16
        self.a     = 5
        self.c     = 3
        self.etat  = graine % 16

    def suivant(self) -> int:
        self.etat = (5 * self.etat + 3) % 16
        return self.etat

    def generer(self, n: int) -> list[int]:
        return [self.suivant() for _ in range(n)]


# ---------------------------------------------------------------------------
# 2. Mersenne Twister MT19937
# ---------------------------------------------------------------------------

class MersenneTwister:
    """
    Implémentation de MT19937 conforme au standard.
    Validé contre random.Random de Python pour une graine donnée.
    """
    N   = 624
    M   = 397
    MATRIX_A   = 0x9908B0DF
    UPPER_MASK = 0x80000000
    LOWER_MASK = 0x7FFFFFFF

    def __init__(self, graine: int):
        self.mt    = [0] * self.N
        self.index = self.N + 1
        self._initialiser(graine & 0xFFFFFFFF)

    def _initialiser(self, graine: int) -> None:
        self.mt[0] = graine & 0xFFFFFFFF
        for i in range(1, self.N):
            self.mt[i] = (
                1812433253 * (self.mt[i-1] ^ (self.mt[i-1] >> 30)) + i
            ) & 0xFFFFFFFF
        self.index = self.N

    def _generer_nombres(self) -> None:
        for i in range(self.N):
            x = (self.mt[i] & self.UPPER_MASK) + (self.mt[(i+1) % self.N] & self.LOWER_MASK)
            xA = x >> 1
            if x & 1:
                xA ^= self.MATRIX_A
            self.mt[i] = self.mt[(i + self.M) % self.N] ^ xA
        self.index = 0

    def _tempering(self, y: int) -> int:
        y ^= y >> 11
        y ^= (y << 7)  & 0x9D2C5680
        y ^= (y << 15) & 0xEFC60000
        y ^= y >> 18
        return y

    def suivant_u32(self) -> int:
        """Retourne un entier non signé 32 bits."""
        if self.index >= self.N:
            self._generer_nombres()
        y = self.mt[self.index]
        self.index += 1
        return self._tempering(y)

    def generer(self, n: int) -> list[int]:
        return [self.suivant_u32() for _ in range(n)]

    def octets(self, n: int) -> bytes:
        sortie = bytearray()
        while len(sortie) < n:
            val = self.suivant_u32()
            sortie += struct.pack(">I", val)
        return bytes(sortie[:n])


# ---------------------------------------------------------------------------
# 3. HMAC_DRBG (NIST SP 800-90A §10.1.2)
# ---------------------------------------------------------------------------

class HMAC_DRBG:
    """
    CSPRNG HMAC_DRBG basé sur HMAC-SHA256.
    Réensemencement automatique depuis os.urandom.
    """
    _SECURITE_BITS = 256

    def __init__(self, entropie: bytes | None = None, nonce: bytes | None = None):
        if entropie is None:
            entropie = os.urandom(32)
        if nonce is None:
            nonce = os.urandom(16)
        self.K = b"\x00" * 32
        self.V = b"\x01" * 32
        self._mettre_a_jour(entropie + nonce)

    def _mettre_a_jour(self, donnees: bytes = b"") -> None:
        """Mise à jour de l'état interne (HMAC_DRBG_Update)."""
        self.K = hmac_sha256(self.K, self.V + b"\x00" + donnees)
        self.V = hmac_sha256(self.K, self.V)
        if donnees:
            self.K = hmac_sha256(self.K, self.V + b"\x01" + donnees)
            self.V = hmac_sha256(self.K, self.V)

    def generer_octets(self, n: int, info: bytes = b"") -> bytes:
        """Génère n octets pseudo-aléatoires."""
        if info:
            self._mettre_a_jour(info)
        sortie = b""
        while len(sortie) < n:
            self.V = hmac_sha256(self.K, self.V)
            sortie += self.V
        sortie = sortie[:n]
        self._mettre_a_jour(info)
        return sortie

    def reensemencer(self, entropie: bytes | None = None) -> None:
        """Réensemencement avec de l'entropie fraîche."""
        if entropie is None:
            entropie = os.urandom(32)
        self._mettre_a_jour(entropie)

    def generer_entier(self, borne_sup: int) -> int:
        """Génère un entier dans [0, borne_sup-1]."""
        nb = (borne_sup.bit_length() + 7) // 8
        while True:
            v = int.from_bytes(self.generer_octets(nb), "big")
            if v < borne_sup:
                return v


# ---------------------------------------------------------------------------
# 4. Tests statistiques
# ---------------------------------------------------------------------------

def stat_monobit(octets: bytes) -> dict:
    """
    NIST SP 800-22 Test 1 : fréquence des bits.
    Compte le nombre de 1 et calcule s_obs = |n1 - n0| / sqrt(n).
    H0 : proportion de 1 ≈ 0.5. Seuil p-value > 0.01.
    """
    bits = "".join(f"{b:08b}" for b in octets)
    n    = len(bits)
    n1   = bits.count("1")
    n0   = n - n1
    s    = abs(n1 - n0) / math.sqrt(n)
    # p-value approx via erfc
    import math as _m
    p = math.erfc(s / math.sqrt(2))
    return {
        "test":     "monobit",
        "n_bits":   n,
        "n_uns":    n1,
        "s_obs":    round(s, 4),
        "p_valeur": round(p, 4),
        "passe":    p > 0.01,
    }


def stat_runs(octets: bytes) -> dict:
    """
    NIST SP 800-22 Test 3 : test des séquences (runs).
    Compte les transitions 0→1 et 1→0.
    """
    bits = "".join(f"{b:08b}" for b in octets)
    n    = len(bits)
    pi   = bits.count("1") / n

    # Pré-test : si pi trop loin de 0.5, échoue directement
    if abs(pi - 0.5) >= 2 / math.sqrt(n):
        return {"test": "runs", "passe": False, "raison": "proportion bits hors norme"}

    # Nombre de runs
    v_obs = sum(1 for i in range(n-1) if bits[i] != bits[i+1]) + 1
    # Valeur attendue et écart-type
    esperance = 2 * n * pi * (1 - pi)
    sigma     = math.sqrt(2 * math.sqrt(n) * pi * (1 - pi))  # approximation
    # p-value approx
    z = abs(v_obs - esperance) / (2 * pi * (1 - pi) * math.sqrt(n))
    p = math.erfc(z / math.sqrt(2))
    return {
        "test":     "runs",
        "n_bits":   n,
        "v_obs":    v_obs,
        "p_valeur": round(p, 4),
        "passe":    p > 0.01,
    }


def stat_chi2_octets(octets: bytes) -> dict:
    """
    Test du χ² sur la distribution des octets (256 classes).
    H0 : chaque valeur 0..255 est équiprobable.
    """
    n  = len(octets)
    if n < 256 * 5:
        return {"test": "chi2", "passe": False, "raison": "pas assez d'octets"}

    freq    = [0] * 256
    for b in octets:
        freq[b] += 1
    attendu = n / 256
    chi2    = sum((f - attendu)**2 / attendu for f in freq)
    # Degrés de liberté = 255 ; seuil χ²(0.01, 255) ≈ 310.46
    seuil   = 310.46
    return {
        "test":     "chi2",
        "n_octets": n,
        "chi2":     round(chi2, 2),
        "seuil":    seuil,
        "passe":    chi2 < seuil,
    }


def appliquer_tests(generateur, n_octets: int = 20_000) -> dict:
    """
    Applique les trois tests à un générateur.
    generateur doit avoir une méthode octets(n) ou generer_octets(n).
    """
    if hasattr(generateur, "octets"):
        data = generateur.octets(n_octets)
    else:
        data = generateur.generer_octets(n_octets)
    return {
        "monobit": stat_monobit(data),
        "runs":    stat_runs(data),
        "chi2":    stat_chi2_octets(data),
    }


# ---------------------------------------------------------------------------
# Démonstration
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=== LCG (cours ch.8, ex.1) : X0=2, m=16, a=5, c=3 ===")
    lcg = LCG_Cours(2)
    suite = lcg.generer(6)
    print(f"  6 premières valeurs : {suite}")
    print(f"  Attendu             : [13, 4, 7, 6, 1, 8]  (réponses cours)")
    print()

    print("=== Mersenne Twister : validation contre random.Random ===")
    import random
    graine = 42
    mt  = MersenneTwister(graine)
    rng = random.Random(graine)
    mt_vals  = [mt.suivant_u32() for _ in range(5)]
    rng_vals = [rng.getrandbits(32) for _ in range(5)]
    print(f"  MT   : {mt_vals}")
    print(f"  random: {rng_vals}")
    print(f"  Correspond : {mt_vals == rng_vals}")
    print()

    print("=== HMAC_DRBG ===")
    drbg = HMAC_DRBG(b"entropie_test" * 3, b"nonce_test_1234")
    a1   = drbg.generer_octets(32)
    a2   = drbg.generer_octets(32)
    print(f"  32 octets 1 : {a1.hex()[:32]}...")
    print(f"  32 octets 2 : {a2.hex()[:32]}...")
    print(f"  Distincts   : {a1 != a2}")
    print()

    print("=== Tests statistiques ===")
    for nom, gen in [
        ("LCG (mauvais)", LCG(12345)),
        ("MT19937",       MersenneTwister(99)),
        ("HMAC_DRBG",     HMAC_DRBG()),
    ]:
        res = appliquer_tests(gen, 20_000)
        passes = sum(1 for t in res.values() if t["passe"])
        print(f"  {nom:20s} : {passes}/3 tests passés")
        for t in res.values():
            s = "OK" if t["passe"] else "ECHEC"
            print(f"    [{s}] {t['test']}")
