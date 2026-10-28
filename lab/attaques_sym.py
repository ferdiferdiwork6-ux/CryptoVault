"""
Attaques pédagogiques sur la cryptographie symétrique (module 6).
- Démonstration ECB (motif visible)
- Attaque bit-flipping sur CBC non authentifié
- OTP : réutilisation de clé
"""
from __future__ import annotations
import os
from cryptolib.symmetric import (
    aes_ecb_chiffrer, aes_ecb_dechiffrer,
    aes_cbc_chiffrer, aes_cbc_dechiffrer,
    aes_gcm_chiffrer, aes_gcm_dechiffrer,
    pkcs7_pad, pkcs7_unpad,
    otp_chiffrer, attaque_otp_reutilisation,
)


# ---------------------------------------------------------------------------
# Attaque 1 : ECB — blocs identiques → chiffrés identiques
# ---------------------------------------------------------------------------

def demo_ecb_motif(cle: bytes | None = None) -> dict:
    """
    Chiffre un message avec des blocs répétés en ECB et en CBC.
    Montre que ECB révèle la structure, pas CBC.
    """
    if cle is None:
        cle = os.urandom(16)

    # Message avec blocs répétés (simule une image uniforme)
    bloc = b"AAAAAAAAAAAAAAAA"   # 16 octets identiques
    message = bloc * 4

    chiffre_ecb = aes_ecb_chiffrer(cle, message)
    iv = os.urandom(16)
    chiffre_cbc = aes_cbc_chiffrer(cle, iv, message)

    # En ECB : blocs 0,1,2,3 chiffrés doivent être identiques
    blocs_ecb = [chiffre_ecb[i*16:(i+1)*16] for i in range(4)]
    blocs_cbc = [chiffre_cbc[i*16:(i+1)*16] for i in range(4)]

    ecb_repete = all(b == blocs_ecb[0] for b in blocs_ecb)
    cbc_repete = all(b == blocs_cbc[0] for b in blocs_cbc)

    return {
        "ecb_blocs_identiques": ecb_repete,   # True  — faille ECB
        "cbc_blocs_identiques": cbc_repete,   # False — CBC masque
        "explication": (
            "En ECB, un même bloc en clair produit toujours le même bloc chiffré. "
            "Le motif de l'image reste visible. En CBC, le chaînage brise ce motif."
        ),
    }


# ---------------------------------------------------------------------------
# Attaque 2 : Bit-flipping sur CBC non authentifié
# ---------------------------------------------------------------------------

def _construire_message_cbc(cle: bytes, iv: bytes) -> tuple[bytes, bytes]:
    """
    Simule un cookie chiffré en CBC.
    Bloc 0 (16o) : 'AAAAAAAAAAAAAAAA'  (sacrifié par l'attaque)
    Bloc 1 (16o) : 'BBBBBBBBBBBBBBBB'  (rembourrage)
    Bloc 2 (16o) : 'AAAAAAA;admin=0B'  <- on veut changer '0' en '1'
    Bloc 3 (16o) : padding PKCS#7
    """
    # ;admin=0 commence à l'offset 7 du bloc 2, donc le '0' est à l'offset 14
    bloc0 = b"A" * 16
    bloc1 = b"B" * 16
    bloc2 = b"A" * 7 + b";admin=0" + b"B"
    message = bloc0 + bloc1 + bloc2
    return aes_cbc_chiffrer(cle, iv, message), message

def attaque_bit_flipping_cbc(cle: bytes, iv: bytes) -> dict:
    """
    Flipping de C[1][14] pour modifier M[2][14] : '0' → '1'.
    En CBC : M[i] = D(C[i]) XOR C[i-1]
    Donc flipping C[i-1][j] flippe M[i][j] de façon prévisible.
    On cible l'octet 14 du bloc 2 via l'octet 14 du bloc 1 chiffré.
    Le bloc 1 sera corrompu à la lecture mais le serveur lit le bloc 2.
    """
    chiffre, message_orig = _construire_message_cbc(cle, iv)

    # ;admin=0 est dans bloc2[7:15], le '0' est à bloc2[14]
    # On modifie C[1][14] pour que M[2][14] passe de '0' à '1'
    chiffre_modifie = bytearray(chiffre)
    chiffre_modifie[16 + 14] ^= ord('0') ^ ord('1')
    chiffre_modifie = bytes(chiffre_modifie)

    # Déchiffrer (le bloc 1 sera corrompu, mais le bloc 2 est contrôlé)
    try:
        dechiffre = aes_cbc_dechiffrer(cle, iv, chiffre_modifie)
    except Exception:
        dechiffre = b""

    admin_original = b"admin=0" in message_orig
    admin_modifie  = b"admin=1" in dechiffre

    return {
        "message_original":  message_orig,
        "dechiffre_modifie": dechiffre,
        "admin_avant":       admin_original,
        "admin_apres":       admin_modifie,
        "attaque_reussie":   admin_modifie,
        "explication": (
            "CBC : M[i] = D(C[i]) XOR C[i-1]. Modifier C[i-1][j] flippe M[i][j]. "
            "Sans authentification, l'attaquant contrôle le clair déchiffré. "
            "AES-GCM détecte cette modification."
        ),
    }

def demo_gcm_detecte_modification(cle: bytes) -> dict:
    """
    Montre que AES-GCM rejette un chiffré modifié (contrairement à CBC).
    """
    nonce   = os.urandom(12)
    message = b"comment1=cooking%20MaCles;admin=0"
    chiffre, tag = aes_gcm_chiffrer(cle, nonce, message)

    # Modifier un bit du chiffré
    chiffre_modifie = bytearray(chiffre)
    chiffre_modifie[-1] ^= 0x01
    chiffre_modifie = bytes(chiffre_modifie)

    gcm_rejette = False
    try:
        aes_gcm_dechiffrer(cle, nonce, chiffre_modifie, tag)
    except ValueError:
        gcm_rejette = True

    return {
        "gcm_rejette_modification": gcm_rejette,
        "explication": (
            "AES-GCM calcule un tag d'authentification sur le chiffré. "
            "Toute modification (même 1 bit) invalide le tag et est détectée."
        ),
    }


# ---------------------------------------------------------------------------
# Attaque 3 : OTP — réutilisation de clé
# ---------------------------------------------------------------------------

def demo_otp_reutilisation() -> dict:
    """
    Alice et Bob réutilisent la même clé OTP pour deux messages.
    L'attaquant obtient M1 XOR M2 et peut souvent retrouver les messages.
    """
    cle = os.urandom(32)
    m1  = b"Le secret est 42"[:16] + b"\x00" * 16
    m2  = b"Mon mot de passe"[:16] + b"\x00" * 16

    c1 = otp_chiffrer(m1[:32], cle)
    c2 = otp_chiffrer(m2[:32], cle)

    xor_messages = attaque_otp_reutilisation(c1, c2)
    xor_attendu  = bytes(a ^ b for a, b in zip(m1[:32], m2[:32]))

    return {
        "xor_messages_obtenu": xor_messages.hex(),
        "xor_messages_reel":   xor_attendu.hex(),
        "correct":             xor_messages == xor_attendu,
        "cle_eliminee":        True,
        "explication": (
            "C1 XOR C2 = (M1 XOR K) XOR (M2 XOR K) = M1 XOR M2. "
            "La clé s'annule. Avec des suppositions sur l'un des messages "
            "(attaque par texte clair supposé), on retrouve l'autre."
        ),
    }


if __name__ == "__main__":
    cle = os.urandom(16)
    iv  = os.urandom(16)

    print("=" * 60)
    print("ATTAQUE 1 : ECB — motif visible")
    print("=" * 60)
    res = demo_ecb_motif(cle)
    print(f"  ECB blocs identiques : {res['ecb_blocs_identiques']}  (faille)")
    print(f"  CBC blocs identiques : {res['cbc_blocs_identiques']}  (sûr)")
    print(f"  {res['explication']}")
    print()

    print("=" * 60)
    print("ATTAQUE 2a : Bit-flipping CBC")
    print("=" * 60)
    res2 = attaque_bit_flipping_cbc(cle, iv)
    print(f"  admin=0 avant : {res2['admin_avant']}")
    print(f"  admin=1 après : {res2['admin_apres']}")
    print(f"  Attaque réussie : {res2['attaque_reussie']}")
    print(f"  {res2['explication']}")
    print()

    print("=" * 60)
    print("ATTAQUE 2b : GCM détecte la modification")
    print("=" * 60)
    res3 = demo_gcm_detecte_modification(cle)
    print(f"  GCM rejette : {res3['gcm_rejette_modification']}")
    print(f"  {res3['explication']}")
    print()

    print("=" * 60)
    print("ATTAQUE 3 : OTP — réutilisation de clé")
    print("=" * 60)
    res4 = demo_otp_reutilisation()
    print(f"  XOR correct  : {res4['correct']}")
    print(f"  Clé éliminée : {res4['cle_eliminee']}")
    print(f"  {res4['explication']}")
