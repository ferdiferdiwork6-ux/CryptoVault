"""
Attaques pédagogiques sur Diffie-Hellman (module 4).
- Attaque de l'homme du milieu (MITM)
- Baby-step Giant-step (BSGS) sur petit premier
"""
from __future__ import annotations
import math
import time
from cryptolib.numtheory import expmod, inverse_mod
from cryptolib.hashing import hmac_sha256


# ---------------------------------------------------------------------------
# Attaque 1 : Homme du milieu (MITM) sur DH non authentifié
# ---------------------------------------------------------------------------

class Mallory:
    """
    Intercepte l'échange DH entre Alice et Bob.
    Établit deux secrets distincts, un avec chaque partie.
    """
    def __init__(self, p: int, g: int):
        self.p = p
        self.g = g
        # Générer la clé de Mallory
        import os
        nb = (p.bit_length() + 7) // 8
        self.m = int.from_bytes(os.urandom(nb), "big") % (p - 2) + 2
        self.M = expmod(g, self.m, p)

    def intercepter_A(self, A: int) -> int:
        """Reçoit A d'Alice, mémorise, renvoie M à Bob."""
        self.A_alice = A
        self.K_alice = expmod(A, self.m, self.p)   # secret avec Alice
        return self.M

    def intercepter_B(self, B: int) -> int:
        """Reçoit B de Bob, mémorise, renvoie M à Alice."""
        self.B_bob = B
        self.K_bob = expmod(B, self.m, self.p)     # secret avec Bob
        return self.M

    def lire_message_alice(self, chiffre: bytes, nonce: bytes) -> bytes:
        """Déchiffre un message envoyé par Alice (avec K_alice)."""
        from cryptolib.symmetric import aes_gcm_dechiffrer
        from cryptolib.dh import hkdf
        cle = hkdf(self.K_alice.to_bytes((self.p.bit_length()+7)//8, "big"), 32)
        # Extraire tag (16 derniers octets) et chiffré
        tag     = chiffre[-16:]
        chiffre = chiffre[:-16]
        return aes_gcm_dechiffrer(cle, nonce, chiffre, tag)

    def relayer_vers_bob(self, clair: bytes) -> tuple[bytes, bytes]:
        """Re-chiffre le message pour Bob avec K_bob."""
        from cryptolib.symmetric import aes_gcm_chiffrer
        from cryptolib.dh import hkdf
        import os
        cle   = hkdf(self.K_bob.to_bytes((self.p.bit_length()+7)//8, "big"), 32)
        nonce = os.urandom(12)
        chiffre, tag = aes_gcm_chiffrer(cle, nonce, clair)
        return chiffre + tag, nonce


def simuler_mitm(p: int, g: int) -> dict:
    """
    Simule une attaque MITM complète sur un échange DH non authentifié.
    Retourne les détails de l'attaque.
    """
    import os
    from cryptolib.numtheory import expmod
    from cryptolib.dh import hkdf
    from cryptolib.symmetric import aes_gcm_chiffrer, aes_gcm_dechiffrer

    nb = (p.bit_length() + 7) // 8

    # Alice génère son secret
    a = int.from_bytes(os.urandom(nb), "big") % (p - 2) + 2
    A = expmod(g, a, p)

    # Bob génère son secret
    b = int.from_bytes(os.urandom(nb), "big") % (p - 2) + 2
    B = expmod(g, b, p)

    # Mallory s'interpose
    mallory = Mallory(p, g)
    A_recu_par_bob  = mallory.intercepter_A(A)   # Bob reçoit M au lieu de A
    B_recu_par_alice = mallory.intercepter_B(B)  # Alice reçoit M au lieu de B

    # Alice calcule son secret avec ce qu'elle croit être B
    K_alice = expmod(B_recu_par_alice, a, p)   # = g^(a*m)

    # Bob calcule son secret avec ce qu'il croit être A
    K_bob   = expmod(A_recu_par_bob,  b, p)   # = g^(b*m)

    # Mallory connaît les deux
    assert K_alice == mallory.K_alice
    assert K_bob   == mallory.K_bob

    # Alice chiffre un message
    cle_alice = hkdf(K_alice.to_bytes(nb, "big"), 32)
    nonce_a   = os.urandom(12)
    message   = b"Message secret d'Alice"
    chiffre_a, tag_a = aes_gcm_chiffrer(cle_alice, nonce_a, message)

    # Mallory lit le message
    cle_mallory_alice = hkdf(mallory.K_alice.to_bytes(nb, "big"), 32)
    message_lu = aes_gcm_dechiffrer(cle_mallory_alice, nonce_a, chiffre_a, tag_a)

    # Mallory relaie vers Bob (éventuellement modifié)
    cle_mallory_bob = hkdf(mallory.K_bob.to_bytes(nb, "big"), 32)
    nonce_m = os.urandom(12)
    message_modifie = message_lu.replace(b"Alice", b"Mallory")
    chiffre_m, tag_m = aes_gcm_chiffrer(cle_mallory_bob, nonce_m, message_modifie)

    # Bob déchiffre
    cle_bob = hkdf(K_bob.to_bytes(nb, "big"), 32)
    message_bob = aes_gcm_dechiffrer(cle_bob, nonce_m, chiffre_m, tag_m)

    return {
        "message_original":   message,
        "message_lu_mallory": message_lu,
        "message_recu_bob":   message_bob,
        "mallory_a_lu":       message_lu == message,
        "message_modifie":    message_bob != message,
        "alice_detecte_mitm": False,   # DH non authentifié : Alice ne sait pas
        "bob_detecte_mitm":   False,
    }


def simuler_mitm_avec_signatures(p: int, g: int) -> dict:
    """
    Même scénario, mais Alice et Bob signent leurs valeurs DH avec RSA.
    Mallory ne peut plus remplacer les valeurs sans invalider la signature.
    """
    import os
    from cryptolib.numtheory import expmod
    from cryptolib.rsa import generer_cles_rsa, signer_rsa, verifier_signature_rsa

    nb = (p.bit_length() + 7) // 8

    # Alice et Bob ont des clés RSA (certificats dans le vrai monde)
    cles_alice = generer_cles_rsa(bits=256)
    cles_bob   = generer_cles_rsa(bits=256)

    # Alice
    a = int.from_bytes(os.urandom(max(nb, 4)), "big") % (p - 2) + 2
    A = expmod(g, a, p)
    sig_A = signer_rsa(A.to_bytes(nb, "big"), cles_alice["privee"])

    # Bob
    b = int.from_bytes(os.urandom(max(nb, 4)), "big") % (p - 2) + 2
    B = expmod(g, b, p)
    sig_B = signer_rsa(B.to_bytes(nb, "big"), cles_bob["privee"])

    # Mallory essaie de substituer ses propres valeurs
    mallory = Mallory(p, g)
    # Mallory envoie M à Bob en prétendant que c'est A, avec la sig d'Alice
    # Mais la signature porte sur A.to_bytes(), pas sur M.to_bytes()

    # Bob vérifie la signature sur la valeur reçue (M de Mallory)
    sig_valide_cote_bob = verifier_signature_rsa(
        mallory.M.to_bytes(nb, "big"),   # valeur reçue (M ≠ A)
        sig_A,                            # signature originale d'Alice
        cles_alice["publique"],
    )

    # Alice vérifie la signature sur la valeur reçue (M de Mallory)
    sig_valide_cote_alice = verifier_signature_rsa(
        mallory.M.to_bytes(nb, "big"),
        sig_B,
        cles_bob["publique"],
    )

    return {
        "sig_valide_cote_bob":   sig_valide_cote_bob,
        "sig_valide_cote_alice": sig_valide_cote_alice,
        "mitm_detecte":          not sig_valide_cote_bob and not sig_valide_cote_alice,
        "explication": (
            "Les signatures RSA portent sur les valeurs DH originales. "
            "Mallory ne peut pas signer avec la clé privée d'Alice/Bob, "
            "donc les vérifications échouent et l'attaque est détectée."
        ),
    }


# ---------------------------------------------------------------------------
# Attaque 2 : Baby-step Giant-step (BSGS) sur logarithme discret
# ---------------------------------------------------------------------------

def bsgs(g: int, h: int, p: int, ordre: int | None = None) -> int | None:
    """
    Baby-step Giant-step pour résoudre h = g^x mod p.
    Complexité O(√ordre) en temps et en espace.
    Retourne x ou None si pas trouvé dans la plage [0, ordre-1].
    """
    if ordre is None:
        ordre = p - 1

    m = math.isqrt(ordre) + 1   # ceil(sqrt(ordre))

    # Baby steps : table[g^j mod p] = j  pour j = 0..m-1
    table = {}
    gj = 1
    for j in range(m):
        table[gj] = j
        gj = (gj * g) % p

    # Giant steps : calculer h * (g^(-m))^i mod p  pour i = 0..m-1
    g_inv_m = expmod(inverse_mod(g, p), m, p)   # = g^(-m) mod p
    gamma   = h
    for i in range(m):
        if gamma in table:
            x = i * m + table[gamma]
            if x < ordre:
                return x
        gamma = (gamma * g_inv_m) % p

    return None   # pas trouvé


def attaque_bsgs_dh(bits_premier: int = 30) -> dict:
    """
    Casse un échange DH sur un petit premier en utilisant BSGS.
    Génère un premier de `bits_premier` bits, simule DH, casse le log discret.
    """
    from cryptolib.numtheory import generate_prime, expmod
    import os

    # Génère un premier de petite taille
    p, _ = generate_prime(bits_premier)
    g = 2

    # Simule DH
    nb = (p.bit_length() + 7) // 8
    a  = int.from_bytes(os.urandom(max(nb, 4)), "big") % (p - 2) + 2
    A  = expmod(g, a, p)

    debut = time.time()
    a_trouve = bsgs(g, A, p, ordre=p - 1)
    duree = time.time() - debut

    succes = a_trouve is not None and expmod(g, a_trouve, p) == A

    return {
        "bits_premier": bits_premier,
        "p":            p,
        "a_reel":       a,
        "a_trouve":     a_trouve,
        "succes":       succes,
        "duree_ms":     round(duree * 1000, 3),
        "complexite_theorique_sqrt": math.isqrt(p - 1),
    }


# ---------------------------------------------------------------------------
# Point d'entrée démonstration
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    from cryptolib.dh import GROUPES

    print("=" * 60)
    print("ATTAQUE 1a : MITM sur DH non authentifié")
    print("=" * 60)
    p, g = GROUPES["demo"]["p"], GROUPES["demo"]["g"]
    res = simuler_mitm(p, g)
    print(f"  Message original      : {res['message_original']}")
    print(f"  Message lu par Mallory: {res['message_lu_mallory']}")
    print(f"  Message reçu par Bob  : {res['message_recu_bob']}")
    print(f"  Mallory a lu          : {res['mallory_a_lu']}")
    print(f"  Message modifié       : {res['message_modifie']}")
    print(f"  Alice détecte MITM    : {res['alice_detecte_mitm']}")
    print()

    print("=" * 60)
    print("ATTAQUE 1b : MITM contré par signatures RSA")
    print("=" * 60)
    res2 = simuler_mitm_avec_signatures(p, g)
    print(f"  Sig valide côté Bob   : {res2['sig_valide_cote_bob']}")
    print(f"  Sig valide côté Alice : {res2['sig_valide_cote_alice']}")
    print(f"  MITM détecté          : {res2['mitm_detecte']}")
    print(f"  {res2['explication']}")
    print()

    print("=" * 60)
    print("ATTAQUE 2 : Baby-step Giant-step (30 bits)")
    print("=" * 60)
    for bits in [20, 25, 30]:
        r = attaque_bsgs_dh(bits)
        print(f"  {bits} bits : p={r['p']}, "
              f"a_reel={r['a_reel']}, a_trouve={r['a_trouve']}, "
              f"succes={r['succes']}, durée={r['duree_ms']} ms, "
              f"sqrt(p-1)≈{r['complexite_theorique_sqrt']}")
