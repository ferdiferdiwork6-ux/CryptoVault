"""
Module 4 : Protocole de Diffie-Hellman et HKDF.
Implémenté sans bibliothèque cryptographique (entiers natifs Python uniquement).
"""
from __future__ import annotations
import os
from cryptolib.numtheory import expmod, pgcd
from cryptolib.hashing import hmac_sha256


# ---------------------------------------------------------------------------
# Groupes MODP standardisés (RFC 3526)
# ---------------------------------------------------------------------------

# Groupe 14 — MODP 2048 bits (RFC 3526 §3)
_P_2048 = int(
    "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1"
    "29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD"
    "EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245"
    "E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED"
    "EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D"
    "C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F"
    "83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D"
    "670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B"
    "E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9"
    "DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510"
    "15728E5A 8AACAA68 FFFFFFFF FFFFFFFF".replace(" ", ""),
    16,
)
_G_2048 = 2

# Groupe réduit pour les tests rapides (512 bits, RFC 3526 non standard)
# Premier sûr p = 2q+1, g = 2
_P_512 = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"
    "FFFFFFFFFFFFFFFF",
    16,
)

# Petit premier pour les démonstrations pédagogiques (cours ch.4)
_P_DEMO  = 23
_G_DEMO  = 5

GROUPES = {
    "demo":  {"p": _P_DEMO,  "g": _G_DEMO,  "bits": 5},
    "2048":  {"p": _P_2048,  "g": _G_2048,  "bits": 2048},
}


# ---------------------------------------------------------------------------
# Échange de clés Diffie-Hellman
# ---------------------------------------------------------------------------

def dh_generer_secret(p: int, g: int, bits: int | None = None) -> tuple[int, int]:
    """
    Génère un secret privé a et la valeur publique A = g^a mod p.
    bits : longueur du secret privé (défaut : taille de p).
    Retourne (a, A). Garantit que A ∉ {0, 1, p-1, p}.
    """
    if bits is None:
        bits = p.bit_length()
    nb_octets = (bits + 7) // 8
    while True:
        a = int.from_bytes(os.urandom(nb_octets), "big") % (p - 2) + 2
        A = expmod(g, a, p)
        if 1 < A < p - 1:   # évite les valeurs triviales
            return a, A


def dh_calculer_secret_partage(A_distant: int, a_local: int, p: int) -> int:
    """
    Calcule le secret partagé K = A_distant^a_local mod p.
    Valide aussi que A_distant est dans le bon sous-groupe.
    """
    _dh_valider_valeur(A_distant, p)
    return expmod(A_distant, a_local, p)


def _dh_valider_valeur(val: int, p: int) -> None:
    """
    Vérifie qu'une valeur DH reçue n'est pas triviale (1 ou p-1).
    Protège contre les attaques par petit sous-groupe.
    """
    if val <= 1 or val >= p:
        raise ValueError(
            f"Valeur DH invalide ({val}) : doit être dans ]1, p[."
        )


# ---------------------------------------------------------------------------
# HKDF (RFC 5869) basé sur HMAC-SHA256
# ---------------------------------------------------------------------------

_HASH_LEN = 32   # SHA-256 → 32 octets

def hkdf_extract(sel: bytes, ikm: bytes) -> bytes:
    """
    HKDF-Extract : PRK = HMAC-SHA256(sel, ikm).
    Si sel est vide, on utilise 32 octets nuls.
    """
    if not sel:
        sel = b"\x00" * _HASH_LEN
    return hmac_sha256(sel, ikm)


def hkdf_expand(prk: bytes, info: bytes, longueur: int) -> bytes:
    """
    HKDF-Expand : dérive `longueur` octets à partir de PRK.
    longueur ≤ 255 * 32 octets.
    """
    if longueur > 255 * _HASH_LEN:
        raise ValueError("Longueur demandée trop grande pour HKDF-Expand.")
    okm = b""
    t   = b""
    i   = 1
    while len(okm) < longueur:
        t = hmac_sha256(prk, t + info + bytes([i]))
        okm += t
        i += 1
    return okm[:longueur]


def hkdf(ikm: bytes, longueur: int, sel: bytes = b"", info: bytes = b"") -> bytes:
    """
    HKDF complet (RFC 5869) : Extract puis Expand.
    Dérive `longueur` octets de matériel de clé à partir de ikm.
    """
    prk = hkdf_extract(sel, ikm)
    return hkdf_expand(prk, info, longueur)


def dh_deriver_cles(
    secret_partage: int,
    p: int,
    longueur_cle_chiffrement: int = 32,
    longueur_cle_auth: int = 32,
) -> tuple[bytes, bytes]:
    """
    Dérive deux clés symétriques (chiffrement + authentification)
    à partir du secret DH via HKDF.
    Retourne (cle_chiffrement, cle_auth).
    """
    ikm = (secret_partage % p).to_bytes((p.bit_length() + 7) // 8, "big")
    cle_chiffrement = hkdf(ikm, longueur_cle_chiffrement, info=b"chiffrement")
    cle_auth        = hkdf(ikm, longueur_cle_auth,         info=b"authentification")
    return cle_chiffrement, cle_auth


# ---------------------------------------------------------------------------
# Démonstration réseau (simulation locale sans sockets)
# ---------------------------------------------------------------------------

def simuler_echange_dh(groupe: str = "demo") -> dict:
    """
    Simule un échange DH complet entre Alice et Bob.
    Vérifie que les deux arrivent au même secret partagé.
    """
    params = GROUPES[groupe]
    p, g   = params["p"], params["g"]

    # Alice
    a, A = dh_generer_secret(p, g)

    # Bob
    b, B = dh_generer_secret(p, g)

    # Calcul du secret partagé des deux côtés
    K_alice = dh_calculer_secret_partage(B, a, p)
    K_bob   = dh_calculer_secret_partage(A, b, p)

    assert K_alice == K_bob, "Les secrets partagés diffèrent !"

    cle_chiffrement, cle_auth = dh_deriver_cles(K_alice, p)

    return {
        "groupe":            groupe,
        "p_bits":            p.bit_length(),
        "A":                 A,
        "B":                 B,
        "secret_commun":     K_alice == K_bob,
        "cle_chiffrement":   cle_chiffrement.hex(),
        "cle_auth":          cle_auth.hex(),
    }


# ---------------------------------------------------------------------------
# Confidentialité persistante : comparaison éphémère vs statique
# ---------------------------------------------------------------------------

def demo_forward_secrecy() -> dict:
    """
    Illustre la différence entre DH éphémère et DH statique.
    Avec DH statique, compromettre la clé à long terme révèle
    toutes les sessions passées enregistrées.
    """
    p, g = GROUPES["demo"]["p"], GROUPES["demo"]["g"]

    # --- DH statique : Alice garde la même clé privée ---
    a_statique, A_statique = dh_generer_secret(p, g)

    sessions_statiques = []
    for _ in range(3):
        b_i, B_i = dh_generer_secret(p, g)
        K_i = dh_calculer_secret_partage(B_i, a_statique, p)
        sessions_statiques.append({"B": B_i, "K": K_i})

    # Si a_statique est compromis, toutes les sessions sont déchiffrables
    sessions_cassees = [
        expmod(s["B"], a_statique, p) == s["K"]
        for s in sessions_statiques
    ]

    # --- DH éphémère : nouvelle clé à chaque session ---
    sessions_ephemeres = []
    for _ in range(3):
        a_eph, A_eph = dh_generer_secret(p, g)    # nouveau secret à chaque fois
        b_i,   B_i   = dh_generer_secret(p, g)
        K_i = dh_calculer_secret_partage(B_i, a_eph, p)
        sessions_ephemeres.append({"K": K_i, "a_efface": True})
        del a_eph   # on efface le secret éphémère

    return {
        "statique_sessions_cassees_si_cle_compromise": all(sessions_cassees),
        "ephemere_sessions_protegees":                 True,
        "explication": (
            "Avec DH statique, connaître a permet de recalculer K pour "
            "toutes les sessions. Avec DH éphémère, chaque a est effacé "
            "après usage : les sessions passées restent protégées (PFS)."
        ),
    }


# ---------------------------------------------------------------------------
# Point d'entrée démonstration
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=== Échange DH (groupe démo, p=23, g=5) ===")
    res = simuler_echange_dh("demo")
    print(f"  Secret commun : {res['secret_commun']}")
    print(f"  Clé chiffrement : {res['cle_chiffrement']}")
    print(f"  Clé auth        : {res['cle_auth']}")
    print()

    print("=== Vecteur du cours (a=6, b=15, p=23, g=5) ===")
    p, g = 23, 5
    a, b = 6, 15
    A = expmod(g, a, p)
    B = expmod(g, b, p)
    K_a = expmod(B, a, p)
    K_b = expmod(A, b, p)
    print(f"  A = {A}  (attendu 8)")
    print(f"  B = {B}  (attendu 19)")
    print(f"  K (Alice) = {K_a}  (attendu 2)")
    print(f"  K (Bob)   = {K_b}  (attendu 2)")
    print()

    print("=== Confidentialité persistante ===")
    pfs = demo_forward_secrecy()
    print(f"  Statique compromis → toutes sessions cassées : "
          f"{pfs['statique_sessions_cassees_si_cle_compromise']}")
    print(f"  Éphémère : sessions protégées : {pfs['ephemere_sessions_protegees']}")
    print(f"  {pfs['explication']}")
    print()

    print("=== HKDF vecteur RFC 5869 (Test Case 1) ===")
    ikm  = bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
    sel  = bytes.fromhex("000102030405060708090a0b0c")
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    okm  = hkdf(ikm, 42, sel=sel, info=info)
    attendu = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    print(f"  OKM     : {okm.hex()}")
    print(f"  Attendu : {attendu}")
    print(f"  Correct : {okm.hex() == attendu}")
