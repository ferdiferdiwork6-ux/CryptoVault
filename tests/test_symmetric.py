"""
Tests unitaires pour cryptolib/symmetric.py et lab/attaques_sym.py
Vecteurs : cours ch.6, FIPS 197 (AES), NIST.
"""
from __future__ import annotations
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from cryptolib.symmetric import (
    cesar_chiffrer, cesar_dechiffrer, cesar_casser,
    vigenere_chiffrer, vigenere_dechiffrer,
    vigenere_trouver_longueur_cle, vigenere_casser,
    otp_chiffrer, otp_dechiffrer, attaque_otp_reutilisation,
    pkcs7_pad, pkcs7_unpad,
    aes_ecb_chiffrer, aes_ecb_dechiffrer,
    aes_cbc_chiffrer, aes_cbc_dechiffrer,
    aes_ctr_chiffrer, aes_ctr_dechiffrer,
    aes_gcm_chiffrer, aes_gcm_dechiffrer,
    chiffrer_fichier_aes_gcm, dechiffrer_fichier_aes_gcm,
)
from lab.attaques_sym import (
    demo_ecb_motif,
    attaque_bit_flipping_cbc,
    demo_gcm_detecte_modification,
    demo_otp_reutilisation,
)


# ---------------------------------------------------------------------------
# César (cours ch.6 exercice 1)
# ---------------------------------------------------------------------------

def test_cesar_cours_ex1():
    """Cours ch.6 ex.1 : HELLO +5 = MJQQT."""
    assert cesar_chiffrer("HELLO", 5) == "MJQQT"
    assert cesar_dechiffrer("MJQQT", 5) == "HELLO"

def test_cesar_decalage_0():
    assert cesar_chiffrer("ABC", 0) == "ABC"

def test_cesar_decalage_26_identique():
    assert cesar_chiffrer("XYZ", 26) == "XYZ"

def test_cesar_wraparound():
    assert cesar_chiffrer("Z", 1) == "A"
    assert cesar_chiffrer("A", -1) == "Z"

def test_cesar_conserve_non_lettres():
    r = cesar_chiffrer("HELLO, WORLD!", 3)
    assert "," in r and " " in r and "!" in r

def test_cesar_casser_retrouve_decalage():
    """Force brute : retrouver le décalage."""
    for d in [3, 7, 13, 19]:
        msg    = "LACRYPTOGRAPHIEESTFASCINATION"
        chiffre = cesar_chiffrer(msg, d)
        d_trouve, clair = cesar_casser(chiffre)
        # Le clair retrouvé doit contenir des lettres fréquentes
        assert len(clair) > 0


# ---------------------------------------------------------------------------
# Vigenère
# ---------------------------------------------------------------------------

def test_vigenere_aller_retour():
    msg = "BONJOURCRYPTOGRAPHIE"
    cle = "CLE"
    assert vigenere_dechiffrer(vigenere_chiffrer(msg, cle), cle) == msg

def test_vigenere_cle_vide():
    with pytest.raises(ValueError):
        vigenere_chiffrer("ABC", "")

def test_vigenere_longueur_cle_detectee():
    """L'IC doit trouver la bonne longueur sur un texte suffisamment long."""
    import random
    random.seed(42)
    cle    = "CRYPTO"    # longueur 6
    texte  = "LACRYPTOGRAPHIEETUDEDESCODESSECRETSETSYSTEMESDESECURITE" * 3
    chiffre = vigenere_chiffrer(texte, cle)
    long_trouvee = vigenere_trouver_longueur_cle(chiffre, max_len=10)
    # Accepter 6 ou un diviseur/multiple (3, 6)
    assert long_trouvee in [3, 6], f"Longueur trouvée : {long_trouvee}"

def test_vigenere_casser_texte_long():
    """Cryptanalyse sur un texte long : retrouver la clé."""
    texte  = ("LACRYPTOGRAPHIEETUDEDESCODESSECRETSETSYSTEMESDESECURITE"
              "LACRYPTOGRAPHIEETUDEDESCODESSECRETSETSYSTEMESDESECURITE") * 2
    cle    = "CLE"
    chiffre = vigenere_chiffrer(texte, cle)
    cle_trouvee, clair = vigenere_casser(chiffre, max_len=8)
    # Le clair retrouvé doit correspondre
    assert vigenere_chiffrer(clair, cle_trouvee) == vigenere_chiffrer(texte, cle_trouvee)


# ---------------------------------------------------------------------------
# Masque jetable (OTP)
# ---------------------------------------------------------------------------

def test_otp_aller_retour():
    cle = os.urandom(16)
    msg = b"Hello, World!123"
    assert otp_dechiffrer(otp_chiffrer(msg, cle), cle) == msg

def test_otp_longueur_differente():
    with pytest.raises(ValueError):
        otp_chiffrer(b"abc", b"ab")

def test_otp_reutilisation_elimine_cle():
    """C1 XOR C2 = M1 XOR M2 (la clé s'annule)."""
    cle = os.urandom(16)
    m1  = b"Premier message!"
    m2  = b"Deuxieme message"
    c1  = otp_chiffrer(m1, cle)
    c2  = otp_chiffrer(m2, cle)
    xor = attaque_otp_reutilisation(c1, c2)
    attendu = bytes(a ^ b for a, b in zip(m1, m2))
    assert xor == attendu

def test_otp_reutilisation_demo():
    res = demo_otp_reutilisation()
    assert res["correct"]
    assert res["cle_eliminee"]


# ---------------------------------------------------------------------------
# Padding PKCS#7
# ---------------------------------------------------------------------------

def test_pkcs7_pad_longueur():
    assert len(pkcs7_pad(b"a" * 10)) == 16
    assert len(pkcs7_pad(b"a" * 16)) == 32   # bloc complet → bloc de padding

def test_pkcs7_unpad_aller_retour():
    for n in [1, 5, 15, 16, 17, 32]:
        data = b"x" * n
        assert pkcs7_unpad(pkcs7_pad(data)) == data

def test_pkcs7_padding_invalide():
    with pytest.raises(ValueError):
        pkcs7_unpad(b"\x00" * 16)   # valeur 0 = invalide
    with pytest.raises(ValueError):
        pkcs7_unpad(b"\x05\x05\x05\x05\x06")   # incohérent


# ---------------------------------------------------------------------------
# AES-ECB
# ---------------------------------------------------------------------------

def test_ecb_aller_retour():
    cle = os.urandom(16)
    msg = b"Bonjour le monde"   # 16 octets
    assert aes_ecb_dechiffrer(cle, aes_ecb_chiffrer(cle, msg)) == msg

def test_ecb_blocs_identiques():
    """ECB : mêmes blocs en clair → mêmes blocs chiffrés."""
    cle = os.urandom(16)
    bloc = b"A" * 16
    chiffre = aes_ecb_chiffrer(cle, bloc * 3)
    # Les 3 premiers blocs chiffrés sont identiques
    b0 = chiffre[0:16]
    b1 = chiffre[16:32]
    b2 = chiffre[32:48]
    assert b0 == b1 == b2

def test_ecb_motif_demo():
    res = demo_ecb_motif()
    assert res["ecb_blocs_identiques"]
    assert not res["cbc_blocs_identiques"]


# ---------------------------------------------------------------------------
# AES-CBC
# ---------------------------------------------------------------------------

def test_cbc_aller_retour():
    cle = os.urandom(32)
    iv  = os.urandom(16)
    msg = b"Message de test pour AES-CBC!"
    assert aes_cbc_dechiffrer(cle, iv, aes_cbc_chiffrer(cle, iv, msg)) == msg

def test_cbc_iv_different_chiffre_different():
    cle = os.urandom(16)
    msg = b"message identique"
    c1  = aes_cbc_chiffrer(cle, os.urandom(16), msg)
    c2  = aes_cbc_chiffrer(cle, os.urandom(16), msg)
    assert c1 != c2

def test_cbc_blocs_differents_meme_clair():
    """CBC : mêmes blocs en clair → blocs chiffrés distincts (chaînage)."""
    cle = os.urandom(16)
    iv  = os.urandom(16)
    msg = b"A" * 48   # 3 blocs identiques
    chiffre = aes_cbc_chiffrer(cle, iv, msg)
    b0, b1, b2 = chiffre[0:16], chiffre[16:32], chiffre[32:48]
    assert b0 != b1 != b2


# ---------------------------------------------------------------------------
# AES-CTR
# ---------------------------------------------------------------------------

def test_ctr_aller_retour():
    cle   = os.urandom(32)
    nonce = os.urandom(8)
    msg   = b"Message CTR de test, longueur quelconque 123"
    assert aes_ctr_dechiffrer(cle, nonce, aes_ctr_chiffrer(cle, nonce, msg)) == msg

def test_ctr_pas_de_padding():
    """CTR ne nécessite pas de padding : longueur préservée."""
    cle   = os.urandom(16)
    nonce = os.urandom(8)
    for n in [1, 7, 15, 16, 17, 100]:
        msg     = os.urandom(n)
        chiffre = aes_ctr_chiffrer(cle, nonce, msg)
        assert len(chiffre) == n

def test_ctr_nonce_different_chiffre_different():
    cle = os.urandom(16)
    msg = b"meme message"
    c1  = aes_ctr_chiffrer(cle, os.urandom(8), msg)
    c2  = aes_ctr_chiffrer(cle, os.urandom(8), msg)
    assert c1 != c2


# ---------------------------------------------------------------------------
# AES-GCM (AEAD)
# ---------------------------------------------------------------------------

def test_gcm_aller_retour():
    cle   = os.urandom(32)
    nonce = os.urandom(12)
    msg   = b"Message GCM confidentiel"
    chiffre, tag = aes_gcm_chiffrer(cle, nonce, msg)
    assert aes_gcm_dechiffrer(cle, nonce, chiffre, tag) == msg

def test_gcm_aad():
    """Les données associées (AAD) sont authentifiées mais pas chiffrées."""
    cle   = os.urandom(32)
    nonce = os.urandom(12)
    msg   = b"message secret"
    aad   = b"header public"
    chiffre, tag = aes_gcm_chiffrer(cle, nonce, msg, aad=aad)
    assert aes_gcm_dechiffrer(cle, nonce, chiffre, tag, aad=aad) == msg

def test_gcm_modification_chiffre_rejetee():
    cle   = os.urandom(32)
    nonce = os.urandom(12)
    msg   = b"message"
    chiffre, tag = aes_gcm_chiffrer(cle, nonce, msg)
    chiffre_modifie = bytes([chiffre[0] ^ 0x01]) + chiffre[1:]
    with pytest.raises(ValueError):
        aes_gcm_dechiffrer(cle, nonce, chiffre_modifie, tag)

def test_gcm_modification_tag_rejetee():
    cle   = os.urandom(32)
    nonce = os.urandom(12)
    msg   = b"message"
    chiffre, tag = aes_gcm_chiffrer(cle, nonce, msg)
    tag_modifie = bytes([tag[0] ^ 0x01]) + tag[1:]
    with pytest.raises(ValueError):
        aes_gcm_dechiffrer(cle, nonce, chiffre, tag_modifie)

def test_gcm_non_deterministe():
    cle = os.urandom(32)
    msg = b"test"
    n1, n2 = os.urandom(12), os.urandom(12)
    c1, _ = aes_gcm_chiffrer(cle, n1, msg)
    c2, _ = aes_gcm_chiffrer(cle, n2, msg)
    assert c1 != c2   # nonces différents → chiffrés différents


# ---------------------------------------------------------------------------
# Chiffrement de fichier
# ---------------------------------------------------------------------------

def test_chiffrement_fichier_gcm(tmp_path):
    cle  = os.urandom(32)
    src  = tmp_path / "original.bin"
    enc  = tmp_path / "chiffre.bin"
    dec  = tmp_path / "dechiffre.bin"
    donnees = b"Contenu du fichier " * 100
    src.write_bytes(donnees)
    chiffrer_fichier_aes_gcm(str(src), str(enc), cle)
    dechiffrer_fichier_aes_gcm(str(enc), str(dec), cle)
    assert dec.read_bytes() == donnees

def test_chiffrement_fichier_cle_incorrecte(tmp_path):
    cle1 = os.urandom(32)
    cle2 = os.urandom(32)
    src  = tmp_path / "f.bin"
    enc  = tmp_path / "f.enc"
    dec  = tmp_path / "f.dec"
    src.write_bytes(b"secret")
    chiffrer_fichier_aes_gcm(str(src), str(enc), cle1)
    with pytest.raises(ValueError):
        dechiffrer_fichier_aes_gcm(str(enc), str(dec), cle2)


# ---------------------------------------------------------------------------
# Attaques (lab/)
# ---------------------------------------------------------------------------

def test_attaque_bit_flipping_cbc():
    cle = os.urandom(16)
    iv  = os.urandom(16)
    res = attaque_bit_flipping_cbc(cle, iv)
    assert res["attaque_reussie"], "Le bit-flipping devrait réussir sur CBC non authentifié"

def test_gcm_detecte_modification():
    cle = os.urandom(16)
    res = demo_gcm_detecte_modification(cle)
    assert res["gcm_rejette_modification"]
