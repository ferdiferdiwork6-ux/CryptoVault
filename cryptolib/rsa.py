"""
Module 3 : Chiffrement RSA
Implémenté sans bibliothèque cryptographique (entiers natifs Python uniquement).
Seul hashlib est autorisé pour le hachage.
"""
from __future__ import annotations
import os
import hashlib
import json
from cryptolib.numtheory import generate_prime, inverse_mod, expmod, egcd, crt


# ---------------------------------------------------------------------------
# Génération de clés RSA
# ---------------------------------------------------------------------------

E_PUBLIC = 65537   # exposant public standard

def generer_cles_rsa(bits: int = 1024) -> dict:
    """
    Génère une paire de clés RSA.
    bits : taille de chaque premier p et q (module = 2*bits).
    Retourne un dict avec clé publique (n, e) et clé privée (d, p, q, dp, dq, qinv).
    """
    while True:
        p, _ = generate_prime(bits)
        q, _ = generate_prime(bits)
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)
        e = E_PUBLIC
        # Vérifier que e est copremier avec phi
        g, _, _ = egcd(e, phi)
        if g != 1:
            continue
        d = inverse_mod(e, phi)
        # Précalculs CRT pour accélérer le déchiffrement
        dp   = d % (p - 1)
        dq   = d % (q - 1)
        qinv = inverse_mod(q, p)
        return {
            "publique": {"n": n, "e": e},
            "privee":   {"d": d, "p": p, "q": q, "dp": dp, "dq": dq, "qinv": qinv},
            "bits_module": n.bit_length(),
        }

def sauvegarder_cles(cles: dict, chemin_pub: str, chemin_priv: str) -> None:
    """Sérialise les clés en JSON (entiers en hexadécimal)."""
    def _to_hex(d):
        return {k: hex(v) if isinstance(v, int) else v for k, v in d.items()}
    with open(chemin_pub, "w") as f:
        json.dump(_to_hex(cles["publique"]), f, indent=2)
    with open(chemin_priv, "w") as f:
        json.dump(_to_hex(cles["privee"]), f, indent=2)

def charger_cle_publique(chemin: str) -> dict:
    with open(chemin) as f:
        d = json.load(f)
    return {k: int(v, 16) for k, v in d.items()}

def charger_cle_privee(chemin: str) -> dict:
    with open(chemin) as f:
        d = json.load(f)
    return {k: int(v, 16) for k, v in d.items()}


# ---------------------------------------------------------------------------
# RSA brut (textbook) — pour les démonstrations et les attaques uniquement
# ---------------------------------------------------------------------------

def rsa_chiffrer_brut(M: int, n: int, e: int) -> int:
    """RSA textbook : C = M^e mod n. NE PAS utiliser en production."""
    if not (0 <= M < n):
        raise ValueError(f"Le message M={M} doit être dans [0, n-1].")
    return expmod(M, e, n)

def rsa_dechiffrer_brut(C: int, d: int, n: int) -> int:
    """RSA textbook sans CRT : M = C^d mod n."""
    return expmod(C, d, n)

def rsa_dechiffrer_crt(C: int, cle_privee: dict) -> int:
    """
    Déchiffrement RSA accéléré par le théorème des restes chinois.
    Environ 4× plus rapide que le déchiffrement direct.
    M = C^d mod n, calculé modulo p et q séparément.
    """
    p, q   = cle_privee["p"], cle_privee["q"]
    dp, dq = cle_privee["dp"], cle_privee["dq"]
    qinv   = cle_privee["qinv"]

    m_p = expmod(C % p, dp, p)
    m_q = expmod(C % q, dq, q)

    # Recombinaison de Garner
    h = (qinv * (m_p - m_q)) % p
    return m_q + h * q


# ---------------------------------------------------------------------------
# Padding OAEP simplifié (MGF1 + SHA-256)
# RFC 8017 §7.1 — version pédagogique
# ---------------------------------------------------------------------------

def _mgf1(seed: bytes, longueur: int, hash_func=hashlib.sha256) -> bytes:
    """Mask Generation Function 1 (RFC 8017 annexe B.2.1)."""
    sortie = b""
    compteur = 0
    while len(sortie) < longueur:
        C = compteur.to_bytes(4, "big")
        sortie += hash_func(seed + C).digest()
        compteur += 1
    return sortie[:longueur]

_HASH_LEN = 32   # SHA-256 → 32 octets

def oaep_encoder(message: bytes, n_octets: int, label: bytes = b"") -> bytes:
    """
    Encodage OAEP (RFC 8017 §7.1.1).
    n_octets : longueur du module RSA en octets.
    """
    k = n_octets
    m_len = len(message)
    max_m = k - 2 * _HASH_LEN - 2
    if m_len > max_m:
        raise ValueError(f"Message trop long ({m_len} > {max_m} octets).")

    l_hash = hashlib.sha256(label).digest()
    ps = b"\x00" * (k - m_len - 2 * _HASH_LEN - 2)
    db = l_hash + ps + b"\x01" + message          # data block

    graine = os.urandom(_HASH_LEN)
    db_mask   = _mgf1(graine, k - _HASH_LEN - 1)
    db_masque = bytes(a ^ b for a, b in zip(db, db_mask))

    seed_mask    = _mgf1(db_masque, _HASH_LEN)
    graine_masque = bytes(a ^ b for a, b in zip(graine, seed_mask))

    return b"\x00" + graine_masque + db_masque

def oaep_decoder(em: bytes, n_octets: int, label: bytes = b"") -> bytes:
    """Décodage OAEP (RFC 8017 §7.1.2)."""
    k = n_octets
    if len(em) != k or k < 2 * _HASH_LEN + 2:
        raise ValueError("Longueur du message encodé invalide.")
    if em[0] != 0:
        raise ValueError("Déchiffrement OAEP : erreur de format.")

    graine_masque = em[1: 1 + _HASH_LEN]
    db_masque     = em[1 + _HASH_LEN:]

    seed_mask = _mgf1(db_masque, _HASH_LEN)
    graine    = bytes(a ^ b for a, b in zip(graine_masque, seed_mask))

    db_mask = _mgf1(graine, k - _HASH_LEN - 1)
    db      = bytes(a ^ b for a, b in zip(db_masque, db_mask))

    l_hash = hashlib.sha256(label).digest()
    if db[:_HASH_LEN] != l_hash:
        raise ValueError("Déchiffrement OAEP : hash du label incorrect.")

    # Trouver le séparateur 0x01
    sep = _HASH_LEN
    while sep < len(db):
        if db[sep] == 1:
            break
        if db[sep] != 0:
            raise ValueError("Déchiffrement OAEP : padding incorrect.")
        sep += 1
    else:
        raise ValueError("Déchiffrement OAEP : séparateur 0x01 introuvable.")

    return db[sep + 1:]


# ---------------------------------------------------------------------------
# Chiffrement / déchiffrement RSA-OAEP (interface principale)
# ---------------------------------------------------------------------------

def chiffrer_rsa(message: bytes, cle_pub: dict) -> bytes:
    """
    Chiffre un message avec RSA-OAEP.
    Le message doit tenir dans un seul bloc (pour les clés de session).
    """
    n = cle_pub["n"]
    e = cle_pub["e"]
    k = (n.bit_length() + 7) // 8

    em = oaep_encoder(message, k)
    m_int = int.from_bytes(em, "big")
    c_int = expmod(m_int, e, n)
    return c_int.to_bytes(k, "big")

def dechiffrer_rsa(chiffre: bytes, cle_privee: dict) -> bytes:
    """Déchiffre un message RSA-OAEP (avec accélération CRT)."""
    n = cle_privee["p"] * cle_privee["q"]
    k = (n.bit_length() + 7) // 8

    c_int = int.from_bytes(chiffre, "big")
    m_int = rsa_dechiffrer_crt(c_int, cle_privee)
    em = m_int.to_bytes(k, "big")
    return oaep_decoder(em, k)


# ---------------------------------------------------------------------------
# Signature RSA (schéma PSS simplifié : sign-the-hash avec padding aléatoire)
# Pour la pédagogie : hash + RSA brut avec sel aléatoire
# ---------------------------------------------------------------------------

def signer_rsa(message: bytes, cle_privee: dict) -> bytes:
    """
    Signature RSA : S = H(message)^d mod n.
    On signe le SHA-256 du message avec la clé privée.
    (Schéma pédagogique, non PSS complet.)
    """
    n = cle_privee["p"] * cle_privee["q"]
    k = (n.bit_length() + 7) // 8

    digest = hashlib.sha256(message).digest()          # 32 octets
    # Padding simple : 0x00 0x01 [0xff...] 0x00 digest
    ps_len = k - len(digest) - 3
    if ps_len < 8:
        raise ValueError("Module RSA trop petit pour la signature.")
    em = b"\x00\x01" + b"\xff" * ps_len + b"\x00" + digest
    m_int = int.from_bytes(em, "big")
    s_int = rsa_dechiffrer_crt(m_int, cle_privee)
    return s_int.to_bytes(k, "big")

def verifier_signature_rsa(message: bytes, signature: bytes, cle_pub: dict) -> bool:
    """Vérifie une signature RSA."""
    n = cle_pub["n"]
    e = cle_pub["e"]
    k = (n.bit_length() + 7) // 8

    if len(signature) != k:
        return False

    s_int = int.from_bytes(signature, "big")
    m_int = expmod(s_int, e, n)
    try:
        em = m_int.to_bytes(k, "big")
    except OverflowError:
        return False

    # Vérifier le format du padding
    if em[0] != 0x00 or em[1] != 0x01:
        return False
    sep = 2
    while sep < len(em) and em[sep] == 0xff:
        sep += 1
    if sep >= len(em) or em[sep] != 0x00:
        return False

    digest_extrait = em[sep + 1:]
    digest_attendu = hashlib.sha256(message).digest()
    # Comparaison en temps constant
    if len(digest_extrait) != len(digest_attendu):
        return False
    diff = 0
    for a, b in zip(digest_extrait, digest_attendu):
        diff |= a ^ b
    return diff == 0


# ---------------------------------------------------------------------------
# Chiffrement hybride : RSA + AES-GCM (clé de session)
# ---------------------------------------------------------------------------

def chiffrer_fichier_hybride(
    donnees: bytes,
    cle_pub: dict,
) -> dict:
    """
    Chiffrement hybride :
      1. Génère une clé AES-256 aléatoire (clé de session).
      2. Chiffre les données avec AES-256-GCM (via le module symmetric).
      3. Chiffre la clé de session avec RSA-OAEP.
    Retourne un dict sérialisable.
    """
    # Import différé pour éviter la dépendance circulaire
    from cryptolib.symmetric import aes_gcm_chiffrer

    cle_session = os.urandom(32)    # AES-256
    nonce       = os.urandom(12)    # GCM standard
    chiffre_sym, tag = aes_gcm_chiffrer(cle_session, nonce, donnees)

    cle_session_chiffree = chiffrer_rsa(cle_session, cle_pub)

    return {
        "cle_session_chiffree": cle_session_chiffree.hex(),
        "nonce":                nonce.hex(),
        "chiffre":              chiffre_sym.hex(),
        "tag":                  tag.hex(),
    }

def dechiffrer_fichier_hybride(
    paquet: dict,
    cle_privee: dict,
) -> bytes:
    """Déchiffre un paquet produit par chiffrer_fichier_hybride."""
    from cryptolib.symmetric import aes_gcm_dechiffrer

    cle_session = dechiffrer_rsa(
        bytes.fromhex(paquet["cle_session_chiffree"]),
        cle_privee,
    )
    nonce   = bytes.fromhex(paquet["nonce"])
    chiffre = bytes.fromhex(paquet["chiffre"])
    tag     = bytes.fromhex(paquet["tag"])
    return aes_gcm_dechiffrer(cle_session, nonce, chiffre, tag)
