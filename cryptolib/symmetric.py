"""
Module 6 : Cryptographie symétrique.
- Chiffrements classiques (César, Vigenère) + cryptanalyse
- Masque jetable (XOR)
- AES : modes ECB, CBC (PKCS#7), CTR, GCM
- Chiffrement authentifié AEAD
"""
from __future__ import annotations
import os
import hashlib
import struct
from cryptolib.hashing import hmac_sha256, comparer_temps_constant


# ---------------------------------------------------------------------------
# Utilitaires alphabet (chiffrements classiques)
# ---------------------------------------------------------------------------

def _normaliser(texte: str) -> str:
    """Majuscules, lettres uniquement."""
    return "".join(c for c in texte.upper() if c.isalpha())


# ---------------------------------------------------------------------------
# Chiffre de César
# ---------------------------------------------------------------------------

def cesar_chiffrer(texte: str, decalage: int) -> str:
    """Chiffre un texte avec le chiffre de César (décalage mod 26)."""
    d = decalage % 26
    res = []
    for c in texte.upper():
        if c.isalpha():
            res.append(chr((ord(c) - ord('A') + d) % 26 + ord('A')))
        else:
            res.append(c)
    return "".join(res)

def cesar_dechiffrer(texte: str, decalage: int) -> str:
    return cesar_chiffrer(texte, -decalage)

def cesar_casser(texte: str) -> tuple[int, str]:
    """Force brute : essaie les 26 décalages, retourne le plus probable (français/anglais)."""
    # Fréquences relatives des lettres en français
    FREQ_FR = "EASITNRULODCMPVQFBGHJXYZ"
    texte_norm = _normaliser(texte)
    meilleur_score = -1
    meilleur_d = 0
    for d in range(26):
        clair = cesar_dechiffrer(texte_norm, d)
        # Score = fréquence des lettres les plus communes
        score = sum(1 for c in clair if c in FREQ_FR[:8])
        if score > meilleur_score:
            meilleur_score = score
            meilleur_d = d
    return meilleur_d, cesar_dechiffrer(texte, meilleur_d)


# ---------------------------------------------------------------------------
# Chiffre de Vigenère
# ---------------------------------------------------------------------------

def vigenere_chiffrer(texte: str, cle: str) -> str:
    cle_norm = _normaliser(cle)
    if not cle_norm:
        raise ValueError("Clé vide.")
    res = []
    j = 0
    for c in texte.upper():
        if c.isalpha():
            d = ord(cle_norm[j % len(cle_norm)]) - ord('A')
            res.append(chr((ord(c) - ord('A') + d) % 26 + ord('A')))
            j += 1
        else:
            res.append(c)
    return "".join(res)

def vigenere_dechiffrer(texte: str, cle: str) -> str:
    cle_norm = _normaliser(cle)
    if not cle_norm:
        raise ValueError("Clé vide.")
    res = []
    j = 0
    for c in texte.upper():
        if c.isalpha():
            d = ord(cle_norm[j % len(cle_norm)]) - ord('A')
            res.append(chr((ord(c) - ord('A') - d) % 26 + ord('A')))
            j += 1
        else:
            res.append(c)
    return "".join(res)

def _indice_coincidence(texte: str) -> float:
    """Calcule l'indice de coïncidence du texte."""
    n = len(texte)
    if n < 2:
        return 0.0
    freq = [texte.count(chr(i + ord('A'))) for i in range(26)]
    return sum(f * (f - 1) for f in freq) / (n * (n - 1))

def vigenere_trouver_longueur_cle(texte: str, max_len: int = 20) -> int:
    """
    Estime la longueur de la clé de Vigenère par l'indice de coïncidence.
    La longueur qui maximise l'IC moyen des sous-séquences est la plus probable.
    IC du français ≈ 0.074, IC aléatoire ≈ 0.038.
    """
    texte_norm = _normaliser(texte)
    meilleur_ic = 0.0
    meilleure_len = 1
    for l in range(1, min(max_len + 1, len(texte_norm) // 2)):
        sous_seq = [texte_norm[i::l] for i in range(l)]
        ic_moyen = sum(_indice_coincidence(s) for s in sous_seq) / l
        if ic_moyen > meilleur_ic:
            meilleur_ic = ic_moyen
            meilleure_len = l
    return meilleure_len

def vigenere_casser(texte: str, max_len: int = 20) -> tuple[str, str]:
    """
    Cryptanalyse de Vigenère : détermine la longueur de clé par IC,
    puis casse chaque sous-séquence par analyse de fréquences (César).
    Retourne (cle_trouvee, texte_dechiffre).
    """
    texte_norm = _normaliser(texte)
    long_cle   = vigenere_trouver_longueur_cle(texte_norm, max_len)

    cle = []
    for i in range(long_cle):
        sous_seq = texte_norm[i::long_cle]
        d, _     = cesar_casser(sous_seq)
        cle.append(chr(d + ord('A')))

    cle_str = "".join(cle)
    return cle_str, vigenere_dechiffrer(texte, cle_str)


# ---------------------------------------------------------------------------
# Masque jetable (One-Time Pad)
# ---------------------------------------------------------------------------

def otp_chiffrer(message: bytes, cle: bytes) -> bytes:
    """XOR message avec cle (masque jetable). len(cle) doit == len(message)."""
    if len(cle) != len(message):
        raise ValueError("La clé doit avoir la même longueur que le message.")
    return bytes(a ^ b for a, b in zip(message, cle))

otp_dechiffrer = otp_chiffrer   # XOR est son propre inverse

def attaque_otp_reutilisation(c1: bytes, c2: bytes) -> bytes:
    """
    Si C1 = M1 ⊕ K et C2 = M2 ⊕ K, alors C1 ⊕ C2 = M1 ⊕ M2.
    Retourne M1 ⊕ M2 qui élimine la clé.
    """
    if len(c1) != len(c2):
        raise ValueError("Les deux chiffrés doivent avoir la même longueur.")
    return bytes(a ^ b for a, b in zip(c1, c2))


# ---------------------------------------------------------------------------
# AES bas niveau (via hashlib — fallback sans pycryptodome)
# On expose une interface cohérente qui délègue à pycryptodome si disponible.
# ---------------------------------------------------------------------------

def _aes_disponible() -> bool:
    try:
        from Crypto.Cipher import AES
        return True
    except ImportError:
        return False

def _aes_ecb_bloc(cle: bytes, bloc: bytes, chiffrer: bool = True) -> bytes:
    """Chiffre/déchiffre un seul bloc AES en ECB."""
    from Crypto.Cipher import AES
    cipher = AES.new(cle, AES.MODE_ECB)
    return cipher.encrypt(bloc) if chiffrer else cipher.decrypt(bloc)


# ---------------------------------------------------------------------------
# Padding PKCS#7
# ---------------------------------------------------------------------------

def pkcs7_pad(data: bytes, taille_bloc: int = 16) -> bytes:
    r = taille_bloc - (len(data) % taille_bloc)
    return data + bytes([r] * r)

def pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        raise ValueError("Données vides.")
    r = data[-1]
    if r == 0 or r > 16:
        raise ValueError(f"Padding PKCS#7 invalide (valeur {r}).")
    if data[-r:] != bytes([r] * r):
        raise ValueError("Padding PKCS#7 corrompu.")
    return data[:-r]


# ---------------------------------------------------------------------------
# Modes AES : ECB, CBC, CTR, GCM
# ---------------------------------------------------------------------------

def aes_ecb_chiffrer(cle: bytes, message: bytes) -> bytes:
    """AES-ECB : ne jamais utiliser en production."""
    from Crypto.Cipher import AES
    padded = pkcs7_pad(message)
    cipher = AES.new(cle, AES.MODE_ECB)
    return cipher.encrypt(padded)

def aes_ecb_dechiffrer(cle: bytes, chiffre: bytes) -> bytes:
    from Crypto.Cipher import AES
    cipher = AES.new(cle, AES.MODE_ECB)
    return pkcs7_unpad(cipher.decrypt(chiffre))

def aes_cbc_chiffrer(cle: bytes, iv: bytes, message: bytes) -> bytes:
    """AES-CBC avec padding PKCS#7."""
    from Crypto.Cipher import AES
    padded = pkcs7_pad(message)
    cipher = AES.new(cle, AES.MODE_CBC, iv=iv)
    return cipher.encrypt(padded)

def aes_cbc_dechiffrer(cle: bytes, iv: bytes, chiffre: bytes) -> bytes:
    from Crypto.Cipher import AES
    cipher = AES.new(cle, AES.MODE_CBC, iv=iv)
    return pkcs7_unpad(cipher.decrypt(chiffre))

def aes_ctr_chiffrer(cle: bytes, nonce: bytes, message: bytes) -> bytes:
    """
    AES-CTR : keystream = AES(cle, nonce || compteur), XOR avec message.
    Nonce : 8 octets, compteur : 8 octets big-endian.
    """
    from Crypto.Cipher import AES
    # pycryptodome CTR : nonce=8 octets, compteur initial = 0
    cipher = AES.new(cle, AES.MODE_CTR, nonce=nonce[:8])
    return cipher.encrypt(message)

aes_ctr_dechiffrer = aes_ctr_chiffrer  # CTR est symétrique

def aes_gcm_chiffrer(
    cle: bytes,
    nonce: bytes,
    message: bytes,
    aad: bytes = b"",
) -> tuple[bytes, bytes]:
    """AES-GCM : retourne (chiffré, tag 16 octets)."""
    from Crypto.Cipher import AES
    cipher = AES.new(cle, AES.MODE_GCM, nonce=nonce)
    if aad:
        cipher.update(aad)
    chiffre, tag = cipher.encrypt_and_digest(message)
    return chiffre, tag

def aes_gcm_dechiffrer(
    cle: bytes,
    nonce: bytes,
    chiffre: bytes,
    tag: bytes,
    aad: bytes = b"",
) -> bytes:
    """AES-GCM : déchiffre et vérifie le tag. Lève ValueError si invalide."""
    from Crypto.Cipher import AES
    cipher = AES.new(cle, AES.MODE_GCM, nonce=nonce)
    if aad:
        cipher.update(aad)
    try:
        return cipher.decrypt_and_verify(chiffre, tag)
    except Exception:
        raise ValueError("Tag GCM invalide : intégrité compromise.")


# ---------------------------------------------------------------------------
# Interface de haut niveau : chiffrement de fichier AES-GCM (mode par défaut)
# ---------------------------------------------------------------------------

def chiffrer_fichier_aes_gcm(
    chemin_entree: str,
    chemin_sortie: str,
    cle: bytes,
) -> bytes:
    """
    Chiffre un fichier avec AES-256-GCM.
    Format : nonce(12) || tag(16) || chiffré
    Retourne le nonce.
    """
    nonce = os.urandom(12)
    with open(chemin_entree, "rb") as f:
        donnees = f.read()
    chiffre, tag = aes_gcm_chiffrer(cle, nonce, donnees)
    with open(chemin_sortie, "wb") as f:
        f.write(nonce + tag + chiffre)
    return nonce

def dechiffrer_fichier_aes_gcm(
    chemin_entree: str,
    chemin_sortie: str,
    cle: bytes,
) -> None:
    """Déchiffre un fichier produit par chiffrer_fichier_aes_gcm."""
    with open(chemin_entree, "rb") as f:
        contenu = f.read()
    nonce   = contenu[:12]
    tag     = contenu[12:28]
    chiffre = contenu[28:]
    clair   = aes_gcm_dechiffrer(cle, nonce, chiffre, tag)
    with open(chemin_sortie, "wb") as f:
        f.write(clair)


# ---------------------------------------------------------------------------
# Démonstration
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=== César ===")
    c = cesar_chiffrer("BONJOUR", 3)
    print(f"  BONJOUR +3 = {c}")
    print(f"  Retour     = {cesar_dechiffrer(c, 3)}")
    d_trouve, clair = cesar_casser(c)
    print(f"  Cassé      : decalage={d_trouve}, clair={clair}")
    print()

    print("=== Vigenère ===")
    chiffre_v = vigenere_chiffrer("BONJOURCRYPTOGRAPHIE", "CLE")
    print(f"  Chiffré : {chiffre_v}")
    print(f"  Retour  : {vigenere_dechiffrer(chiffre_v, 'CLE')}")
    print()

    print("=== OTP ===")
    msg = b"Hello"
    cle = os.urandom(5)
    c1 = otp_chiffrer(msg, cle)
    msg2 = b"World"
    c2 = otp_chiffrer(msg2, cle)
    xor_clairs = attaque_otp_reutilisation(c1, c2)
    print(f"  M1 xor M2 = {xor_clairs}")
    attendu = bytes(a ^ b for a, b in zip(msg, msg2))
    print(f"  Correct   : {xor_clairs == attendu}")
    print()

    if _aes_disponible():
        print("=== AES-GCM ===")
        cle_aes = os.urandom(32)
        nonce   = os.urandom(12)
        data    = b"Message confidentiel"
        chiffre, tag = aes_gcm_chiffrer(cle_aes, nonce, data)
        clair   = aes_gcm_dechiffrer(cle_aes, nonce, chiffre, tag)
        print(f"  Aller-retour : {clair == data}")
    else:
        print("pycryptodome non disponible, AES non testé.")
