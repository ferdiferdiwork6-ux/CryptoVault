"""
Module 5 : Courbes elliptiques — addition de points, ECDH, ECDSA.
Implémenté sans bibliothèque cryptographique (entiers natifs Python uniquement).
"""
from __future__ import annotations
import os
import hashlib
from cryptolib.numtheory import inverse_mod, expmod
from cryptolib.hashing import hmac_sha256


# ---------------------------------------------------------------------------
# Représentation d'un point
# ---------------------------------------------------------------------------

class Point:
    """Point d'une courbe elliptique, ou point à l'infini (INFINI)."""
    __slots__ = ("x", "y")

    def __init__(self, x: int | None, y: int | None):
        self.x = x
        self.y = y

    @property
    def est_infini(self) -> bool:
        return self.x is None

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Point):
            return NotImplemented
        return self.x == other.x and self.y == other.y

    def __repr__(self) -> str:
        if self.est_infini:
            return "Point(∞)"
        return f"Point({self.x}, {self.y})"


INFINI = Point(None, None)   # Point à l'infini (élément neutre)


# ---------------------------------------------------------------------------
# Courbe elliptique : y² = x³ + ax + b (mod p)
# ---------------------------------------------------------------------------

class CourbeElliptique:
    """
    Courbe de Weierstrass sur 𝔽ₚ : y² ≡ x³ + a·x + b (mod p).
    """

    def __init__(self, p: int, a: int, b: int):
        if (4 * pow(a, 3, p) + 27 * pow(b, 2, p)) % p == 0:
            raise ValueError("Courbe singulière (4a³ + 27b² ≡ 0).")
        self.p = p
        self.a = a
        self.b = b

    # --- Vérification ---

    def est_sur_courbe(self, P: Point) -> bool:
        if P.est_infini:
            return True
        lhs = (P.y * P.y) % self.p
        rhs = (P.x**3 + self.a * P.x + self.b) % self.p
        return lhs == rhs

    # --- Loi de groupe ---

    def oppose(self, P: Point) -> Point:
        """Retourne -P = (x, -y mod p)."""
        if P.est_infini:
            return INFINI
        return Point(P.x, (-P.y) % self.p)

    def ajouter(self, P: Point, Q: Point) -> Point:
        """Addition P + Q sur la courbe."""
        if P.est_infini:
            return Q
        if Q.est_infini:
            return P
        if P.x == Q.x:
            if (P.y + Q.y) % self.p == 0:
                return INFINI          # P + (-P) = 𝒪
            return self._doubler(P)    # P == Q

        # Cas général P ≠ Q
        lam = (Q.y - P.y) * inverse_mod(Q.x - P.x, self.p) % self.p
        x3  = (lam * lam - P.x - Q.x) % self.p
        y3  = (lam * (P.x - x3) - P.y) % self.p
        return Point(x3, y3)

    def _doubler(self, P: Point) -> Point:
        """Doublement 2P."""
        if P.est_infini or P.y == 0:
            return INFINI
        lam = (3 * P.x * P.x + self.a) * inverse_mod(2 * P.y, self.p) % self.p
        x3  = (lam * lam - 2 * P.x) % self.p
        y3  = (lam * (P.x - x3) - P.y) % self.p
        return Point(x3, y3)

    def multiplier(self, k: int, P: Point) -> Point:
        """
        Multiplication scalaire k·P par la méthode double-and-add.
        Complexité O(log k) doublements + additions.
        """
        k = k % self.ordre_approximatif() if hasattr(self, "_n") else k
        if k == 0 or P.est_infini:
            return INFINI
        if k < 0:
            return self.multiplier(-k, self.oppose(P))

        resultat = INFINI
        courant  = P
        while k > 0:
            if k & 1:
                resultat = self.ajouter(resultat, courant)
            courant = self.ajouter(courant, courant)
            k >>= 1
        return resultat

    def ordre_approximatif(self) -> int:
        """Retourne l'ordre du groupe si défini, sinon p."""
        return getattr(self, "_n", self.p)


# ---------------------------------------------------------------------------
# Courbes standardisées
# ---------------------------------------------------------------------------

class CourbeAvecParametres(CourbeElliptique):
    """Courbe avec point générateur G et ordre n."""

    def __init__(self, p: int, a: int, b: int, Gx: int, Gy: int, n: int):
        super().__init__(p, a, b)
        self._n = n
        self.G  = Point(Gx, Gy)
        self.n  = n

    def multiplier(self, k: int, P: Point) -> Point:
        k = k % self.n
        if k == 0 or P.est_infini:
            return INFINI
        resultat = INFINI
        courant  = P
        while k > 0:
            if k & 1:
                resultat = self.ajouter(resultat, courant)
            courant = self.ajouter(courant, courant)
            k >>= 1
        return resultat


# Courbe jouet du cours (y² = x³ + 2x + 2 mod 17, ordre 19)
COURBE_JOUET = CourbeAvecParametres(
    p=17, a=2, b=2,
    Gx=5, Gy=1,
    n=19,
)

# NIST P-256 (secp256r1)
_P256_p  = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_P256_a  = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
_P256_b  = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
_P256_Gx = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
_P256_Gy = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
_P256_n  = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

P256 = CourbeAvecParametres(
    p=_P256_p, a=_P256_a, b=_P256_b,
    Gx=_P256_Gx, Gy=_P256_Gy,
    n=_P256_n,
)

# secp256k1 (Bitcoin)
_K256_p  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_K256_a  = 0
_K256_b  = 7
_K256_Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_K256_Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
_K256_n  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

SECP256K1 = CourbeAvecParametres(
    p=_K256_p, a=_K256_a, b=_K256_b,
    Gx=_K256_Gx, Gy=_K256_Gy,
    n=_K256_n,
)

COURBES = {
    "jouet":    COURBE_JOUET,
    "p256":     P256,
    "secp256k1": SECP256K1,
}


# ---------------------------------------------------------------------------
# ECDH
# ---------------------------------------------------------------------------

def ecdh_generer_cle(courbe: CourbeAvecParametres) -> tuple[int, Point]:
    """
    Génère une paire de clés ECDH (clé privée d, clé publique Q = d·G).
    Retourne (d, Q).
    """
    nb = (courbe.n.bit_length() + 7) // 8
    while True:
        d = int.from_bytes(os.urandom(nb), "big") % (courbe.n - 1) + 1
        Q = courbe.multiplier(d, courbe.G)
        if not Q.est_infini:
            return d, Q


def ecdh_secret_partage(d_local: int, Q_distant: Point, courbe: CourbeAvecParametres) -> bytes:
    """
    Calcule le secret partagé ECDH : coordonnée x de d_local · Q_distant.
    """
    if not courbe.est_sur_courbe(Q_distant):
        raise ValueError("Le point distant n'est pas sur la courbe.")
    K = courbe.multiplier(d_local, Q_distant)
    if K.est_infini:
        raise ValueError("Secret partagé invalide (point à l'infini).")
    nb = (courbe.p.bit_length() + 7) // 8
    return K.x.to_bytes(nb, "big")


# ---------------------------------------------------------------------------
# ECDSA (RFC 6979 pour le nonce déterministe)
# ---------------------------------------------------------------------------

def _bits2int(b: bytes, n_bits: int) -> int:
    """Convertit des octets en entier, tronqué si nécessaire (RFC 6979 §2.3.2)."""
    v = int.from_bytes(b, "big")
    if len(b) * 8 > n_bits:
        v >>= len(b) * 8 - n_bits
    return v


def _rfc6979_nonce(d: int, msg_hash: bytes, n: int) -> int:
    """
    Génère un nonce déterministe k selon RFC 6979 §3.2.
    Évite la réutilisation accidentelle de k qui révèle la clé privée.
    """
    nb  = (n.bit_length() + 7) // 8
    h1  = msg_hash
    # Initialisation
    V   = b"\x01" * 32
    K   = b"\x00" * 32
    d_b = d.to_bytes(nb, "big")
    # Étape d
    K = hmac_sha256(K, V + b"\x00" + d_b + h1)
    V = hmac_sha256(K, V)
    K = hmac_sha256(K, V + b"\x01" + d_b + h1)
    V = hmac_sha256(K, V)
    # Génération
    while True:
        T = b""
        while len(T) < nb:
            V = hmac_sha256(K, V)
            T += V
        k = _bits2int(T, n.bit_length())
        if 1 <= k < n:
            return k
        K = hmac_sha256(K, V + b"\x00")
        V = hmac_sha256(K, V)


def ecdsa_signer(
    message: bytes,
    d: int,
    courbe: CourbeAvecParametres,
    nonce_aleatoire: bool = False,
) -> tuple[int, int]:
    """
    Signe un message avec ECDSA.
    Par défaut utilise le nonce déterministe RFC 6979 (recommandé).
    Retourne (r, s).
    """
    n        = courbe.n
    nb       = (n.bit_length() + 7) // 8
    msg_hash = hashlib.sha256(message).digest()
    z        = _bits2int(msg_hash, n.bit_length())

    while True:
        if nonce_aleatoire:
            k = int.from_bytes(os.urandom(nb), "big") % (n - 1) + 1
        else:
            k = _rfc6979_nonce(d, msg_hash, n)

        R = courbe.multiplier(k, courbe.G)
        if R.est_infini:
            continue
        r = R.x % n
        if r == 0:
            continue
        k_inv = inverse_mod(k, n)
        s = k_inv * (z + r * d) % n
        if s == 0:
            continue
        return r, s


def ecdsa_verifier(
    message: bytes,
    signature: tuple[int, int],
    Q: Point,
    courbe: CourbeAvecParametres,
) -> bool:
    """Vérifie une signature ECDSA (r, s)."""
    r, s = signature
    n    = courbe.n

    if not (1 <= r < n and 1 <= s < n):
        return False
    if not courbe.est_sur_courbe(Q) or Q.est_infini:
        return False

    msg_hash = hashlib.sha256(message).digest()
    z   = _bits2int(msg_hash, n.bit_length())
    w   = inverse_mod(s, n)
    u1  = z * w % n
    u2  = r * w % n
    X   = courbe.ajouter(
        courbe.multiplier(u1, courbe.G),
        courbe.multiplier(u2, Q),
    )
    if X.est_infini:
        return False
    return (X.x % n) == r


# ---------------------------------------------------------------------------
# Attaque : réutilisation du nonce ECDSA → retrouver la clé privée
# ---------------------------------------------------------------------------

def attaque_nonce_reutilise(
    message1: bytes,
    sig1: tuple[int, int],
    message2: bytes,
    sig2: tuple[int, int],
    courbe: CourbeAvecParametres,
) -> int | None:
    """
    Si le même nonce k est utilisé pour deux signatures, retrouve d.
    s1 = k⁻¹(z1 + r·d) mod n
    s2 = k⁻¹(z2 + r·d) mod n
    → s1 - s2 = k⁻¹(z1 - z2)  → k = (z1-z2)/(s1-s2) mod n
    → d = (s1·k - z1) / r mod n
    """
    n = courbe.n
    r1, s1 = sig1
    r2, s2 = sig2

    if r1 != r2:
        return None   # nonces différents (r = Rx mod n)

    z1 = _bits2int(hashlib.sha256(message1).digest(), n.bit_length())
    z2 = _bits2int(hashlib.sha256(message2).digest(), n.bit_length())

    try:
        k = (z1 - z2) * inverse_mod(s1 - s2, n) % n
        d = (s1 * k - z1) * inverse_mod(r1, n) % n
    except ValueError:
        return None

    return d if d > 0 else None


# ---------------------------------------------------------------------------
# Point d'entrée démonstration
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=== Courbe jouet (cours ch.5) : y² = x³+2x+2 mod 17 ===")
    C = COURBE_JOUET
    G = C.G

    # Table des multiples
    TABLE_COURS = [
        (1,  5,  1), (2,  6,  3), (3, 10,  6), (4,  3,  1), (5,  9, 16),
        (6, 16, 13), (7,  0,  6), (8, 13,  7), (9,  7,  6), (10, 7, 11),
    ]
    ok = True
    for k, x_att, y_att in TABLE_COURS:
        P = C.multiplier(k, G)
        if P.x != x_att or P.y != y_att:
            print(f"  ERREUR {k}G: attendu ({x_att},{y_att}), obtenu {P}")
            ok = False
    print(f"  Table des multiples 1G..10G : {'OK' if ok else 'ERREUR'}")
    print(f"  19G = {C.multiplier(19, G)}  (attendu ∞)")
    print()

    print("=== ECDH sur courbe jouet ===")
    a_priv, A_pub = 3, C.multiplier(3, G)
    b_priv, B_pub = 5, C.multiplier(5, G)
    K_a = C.multiplier(a_priv, B_pub)
    K_b = C.multiplier(b_priv, A_pub)
    print(f"  A = 3G = {A_pub}  (attendu (10,6))")
    print(f"  B = 5G = {B_pub}  (attendu (9,16))")
    print(f"  K_Alice = {K_a}   K_Bob = {K_b}   Egaux: {K_a == K_b}")
    print()

    print("=== ECDSA sur P-256 ===")
    d, Q = ecdh_generer_cle(P256)
    msg  = b"Bonjour CryptoVault"
    sig  = ecdsa_signer(msg, d, P256)
    ok   = ecdsa_verifier(msg, sig, Q, P256)
    print(f"  Signature valide : {ok}")
    ok2  = ecdsa_verifier(b"message different", sig, Q, P256)
    print(f"  Message modifié rejeté : {not ok2}")
    print()

    print("=== Attaque nonce réutilisé ===")
    msg1, msg2 = b"message1", b"message2"
    # Forcer le même nonce (aléatoire=True mais on fixe manuellement)
    n = P256.n
    nb = (n.bit_length() + 7) // 8
    k_fixe = int.from_bytes(os.urandom(nb), "big") % (n - 1) + 1
    R = P256.multiplier(k_fixe, P256.G)
    r = R.x % n
    z1 = _bits2int(hashlib.sha256(msg1).digest(), n.bit_length())
    z2 = _bits2int(hashlib.sha256(msg2).digest(), n.bit_length())
    k_inv = inverse_mod(k_fixe, n)
    s1 = k_inv * (z1 + r * d) % n
    s2 = k_inv * (z2 + r * d) % n
    d_retrouve = attaque_nonce_reutilise(msg1, (r, s1), msg2, (r, s2), P256)
    print(f"  d retrouvé == d : {d_retrouve == d}")
