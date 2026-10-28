"""
Attaques pédagogiques sur les courbes elliptiques (module 5).
- Réutilisation du nonce ECDSA
- Nonce déterministe RFC 6979 comme contre-mesure
"""
from __future__ import annotations
import os
import hashlib
import time
from cryptolib.ecc import (
    P256, COURBE_JOUET,
    ecdh_generer_cle, ecdsa_signer, ecdsa_verifier,
    attaque_nonce_reutilise, _bits2int, _rfc6979_nonce,
)
from cryptolib.numtheory import inverse_mod


def demo_attaque_nonce_reutilise(courbe=P256) -> dict:
    """
    Génère deux signatures avec le même nonce k et retrouve la clé privée.
    Illustre la catastrophe de la PS3 (2010) et des vols de Bitcoin.
    """
    n  = courbe.n
    nb = (n.bit_length() + 7) // 8

    # Générer une clé légitime
    d, Q = ecdh_generer_cle(courbe)

    # Choisir un nonce fixe (la faille)
    k = int.from_bytes(os.urandom(nb), "big") % (n - 1) + 1
    R = courbe.multiplier(k, courbe.G)
    r = R.x % n

    msg1 = b"Transaction 1"
    msg2 = b"Transaction 2"

    z1 = _bits2int(hashlib.sha256(msg1).digest(), n.bit_length())
    z2 = _bits2int(hashlib.sha256(msg2).digest(), n.bit_length())

    k_inv = inverse_mod(k, n)
    s1 = k_inv * (z1 + r * d) % n
    s2 = k_inv * (z2 + r * d) % n

    debut = time.time()
    d_retrouve = attaque_nonce_reutilise(msg1, (r, s1), msg2, (r, s2), courbe)
    duree = time.time() - debut

    succes = d_retrouve is not None and d_retrouve == d

    return {
        "succes":       succes,
        "d_reel":       d,
        "d_retrouve":   d_retrouve,
        "duree_ms":     round(duree * 1000, 3),
        "explication": (
            "Deux signatures avec le même k révèlent k (algèbre linéaire), "
            "puis d. PlayStation 3 (Sony, 2010) utilisait k constant. "
            "Contre-mesure : nonce déterministe RFC 6979."
        ),
    }


def demo_nonce_deterministe(courbe=P256) -> dict:
    """
    Montre que RFC 6979 produit toujours des nonces distincts
    même pour des messages différents, sans aléa.
    """
    d, Q = ecdh_generer_cle(courbe)
    n    = courbe.n

    messages = [b"msg1", b"msg2", b"msg3", b"msg1"]   # msg1 répété

    nonces = []
    for msg in messages:
        h = hashlib.sha256(msg).digest()
        k = _rfc6979_nonce(d, h, n)
        nonces.append(k)

    # Deux signatures du même message doivent donner le même nonce → même sig
    sig1 = ecdsa_signer(b"msg1", d, courbe, nonce_aleatoire=False)
    sig2 = ecdsa_signer(b"msg1", d, courbe, nonce_aleatoire=False)

    return {
        "nonces_distincts_pour_messages_differents": nonces[0] != nonces[1] != nonces[2],
        "meme_message_meme_nonce":                   nonces[0] == nonces[3],
        "signature_deterministe":                    sig1 == sig2,
        "signature_valide":                          ecdsa_verifier(b"msg1", sig1, Q, courbe),
        "explication": (
            "RFC 6979 dérive k de façon déterministe à partir de (d, h(message)). "
            "Même message → même k → même signature (mais toujours unique par message). "
            "Impossible de réutiliser accidentellement k pour deux messages différents."
        ),
    }


if __name__ == "__main__":
    print("=" * 60)
    print("ATTAQUE : Nonce ECDSA réutilisé (P-256)")
    print("=" * 60)
    res = demo_attaque_nonce_reutilise()
    print(f"  Succès        : {res['succes']}")
    print(f"  Durée         : {res['duree_ms']} ms")
    print(f"  {res['explication']}")
    print()

    print("=" * 60)
    print("CONTRE-MESURE : Nonce déterministe RFC 6979")
    print("=" * 60)
    res2 = demo_nonce_deterministe()
    print(f"  Nonces distincts / messages différents : {res2['nonces_distincts_pour_messages_differents']}")
    print(f"  Même message → même nonce             : {res2['meme_message_meme_nonce']}")
    print(f"  Signature déterministe                : {res2['signature_deterministe']}")
    print(f"  Signature valide                      : {res2['signature_valide']}")
    print(f"  {res2['explication']}")
