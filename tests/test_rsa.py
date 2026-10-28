"""
Tests unitaires pour cryptolib/rsa.py et lab/attaques_rsa.py
"""
from __future__ import annotations
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import time
import pytest
from cryptolib.numtheory import expmod, inverse_mod
from cryptolib.rsa import (
    generer_cles_rsa,
    sauvegarder_cles, charger_cle_publique, charger_cle_privee,
    rsa_chiffrer_brut, rsa_dechiffrer_brut, rsa_dechiffrer_crt,
    oaep_encoder, oaep_decoder,
    chiffrer_rsa, dechiffrer_rsa,
    signer_rsa, verifier_signature_rsa,
    chiffrer_fichier_hybride, dechiffrer_fichier_hybride,
)
from lab.attaques_rsa import (
    attaque_factorisation_64bits,
    attaque_malleabilite,
    attaque_petite_racine,
    attaque_facteur_commun,
    demo_facteur_commun,
)


# ---------------------------------------------------------------------------
# Exemple numérique du cours (p=61, q=53, e=17)
# ---------------------------------------------------------------------------

@pytest.fixture
def cles_cours():
    """Clés RSA de l'exemple du cours chapitre 3."""
    p, q, e = 61, 53, 17
    n   = p * q        # 3233
    phi = (p-1)*(q-1)  # 3120
    d   = inverse_mod(e, phi)  # 2753
    return {
        "publique": {"n": n, "e": e},
        "privee":   {
            "d": d, "p": p, "q": q,
            "dp": d % (p-1), "dq": d % (q-1),
            "qinv": inverse_mod(q, p),
        },
    }


# ---------------------------------------------------------------------------
# RSA textbook (exemple du cours)
# ---------------------------------------------------------------------------

def test_rsa_textbook_exemple_cours(cles_cours):
    """Vecteur cours : M=65, C=2790, déchiffrement=65."""
    n, e = cles_cours["publique"]["n"], cles_cours["publique"]["e"]
    d    = cles_cours["privee"]["d"]
    M, C_attendu = 65, 2790

    C = rsa_chiffrer_brut(M, n, e)
    assert C == C_attendu, f"Chiffrement : attendu {C_attendu}, obtenu {C}"

    M2 = rsa_dechiffrer_brut(C, d, n)
    assert M2 == M

def test_rsa_textbook_exercice_ch3(cles_cours):
    """Exercice cours ch3 : p=11, q=13 → n=143, e=7, d=103, M=9, C=48."""
    p, q, e = 11, 13, 7
    n   = p * q
    phi = (p-1)*(q-1)
    d   = inverse_mod(e, phi)
    assert n == 143
    assert d == 103

    C = expmod(9, e, n)
    assert C == 48
    assert expmod(C, d, n) == 9

def test_rsa_correction_aleatoire(cles_cours):
    """Dec(Enc(M)) == M pour plusieurs messages."""
    n, e = cles_cours["publique"]["n"], cles_cours["publique"]["e"]
    d    = cles_cours["privee"]["d"]
    for M in [1, 42, 100, 3000]:
        C  = rsa_chiffrer_brut(M, n, e)
        M2 = rsa_dechiffrer_brut(C, d, n)
        assert M2 == M, f"Erreur pour M={M}"

def test_rsa_message_hors_intervalle(cles_cours):
    n, e = cles_cours["publique"]["n"], cles_cours["publique"]["e"]
    with pytest.raises(ValueError):
        rsa_chiffrer_brut(n, n, e)   # M = n, hors [0, n-1]


# ---------------------------------------------------------------------------
# Déchiffrement CRT
# ---------------------------------------------------------------------------

def test_crt_meme_resultat_que_direct(cles_cours):
    n, e = cles_cours["publique"]["n"], cles_cours["publique"]["e"]
    priv = cles_cours["privee"]
    for M in [1, 65, 999, 3000]:
        C         = rsa_chiffrer_brut(M, n, e)
        M_direct  = rsa_dechiffrer_brut(C, priv["d"], n)
        M_crt     = rsa_dechiffrer_crt(C, priv)
        assert M_direct == M_crt == M

def test_crt_plus_rapide_que_direct():
    """Le CRT doit être strictement plus rapide sur des clés 512 bits."""
    cles = generer_cles_rsa(bits=256)   # 512 bits total, rapide pour le test
    pub, priv = cles["publique"], cles["privee"]
    n = pub["n"]

    M = 123456789
    C = rsa_chiffrer_brut(M, n, pub["e"])

    ESSAIS = 5
    debut = time.time()
    for _ in range(ESSAIS):
        rsa_dechiffrer_brut(C, priv["d"], n)
    t_direct = time.time() - debut

    debut = time.time()
    for _ in range(ESSAIS):
        rsa_dechiffrer_crt(C, priv)
    t_crt = time.time() - debut

    assert t_crt < t_direct, (
        f"CRT ({t_crt:.4f}s) pas plus rapide que direct ({t_direct:.4f}s)"
    )


# ---------------------------------------------------------------------------
# OAEP
# ---------------------------------------------------------------------------

def test_oaep_encode_decode_aller_retour():
    n_octets = 256   # module 2048 bits
    message  = b"message secret de test OAEP"
    em       = oaep_encoder(message, n_octets)
    assert len(em) == n_octets
    recupere = oaep_decoder(em, n_octets)
    assert recupere == message

def test_oaep_non_deterministe():
    n_octets = 256
    message  = b"test"
    em1 = oaep_encoder(message, n_octets)
    em2 = oaep_encoder(message, n_octets)
    assert em1 != em2   # graine aléatoire → résultats différents

def test_oaep_message_trop_long():
    n_octets = 256   # max = 256 - 2*32 - 2 = 190 octets
    with pytest.raises(ValueError):
        oaep_encoder(b"x" * 200, n_octets)

def test_oaep_corruption_detectee():
    n_octets = 256
    em = oaep_encoder(b"test", n_octets)
    em_corrompu = bytearray(em)
    em_corrompu[10] ^= 0xFF
    with pytest.raises(ValueError):
        oaep_decoder(bytes(em_corrompu), n_octets)


# ---------------------------------------------------------------------------
# Chiffrement / déchiffrement RSA-OAEP complet (clés générées)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def cles_512():
    """Clés RSA avec module de 1024 bits (2×512) pour les tests OAEP."""
    return generer_cles_rsa(bits=512)

def test_chiffrer_dechiffrer_rsa_oaep(cles_512):
    pub, priv = cles_512["publique"], cles_512["privee"]
    message = b"Bonjour CryptoVault !"
    chiffre  = chiffrer_rsa(message, pub)
    clair    = dechiffrer_rsa(chiffre, priv)
    assert clair == message

def test_chiffrement_non_deterministe(cles_512):
    pub = cles_512["publique"]
    m   = b"test"
    assert chiffrer_rsa(m, pub) != chiffrer_rsa(m, pub)

def test_mauvaise_cle_echec(cles_512):
    pub   = cles_512["publique"]
    priv2 = generer_cles_rsa(bits=256)["privee"]
    chiffre = chiffrer_rsa(b"secret", pub)
    with pytest.raises((ValueError, Exception)):
        dechiffrer_rsa(chiffre, priv2)


# ---------------------------------------------------------------------------
# Sérialisation des clés
# ---------------------------------------------------------------------------

def test_serialisation_cles(tmp_path, cles_512):
    chemin_pub  = str(tmp_path / "pub.json")
    chemin_priv = str(tmp_path / "priv.json")
    sauvegarder_cles(cles_512, chemin_pub, chemin_priv)

    pub_charge  = charger_cle_publique(chemin_pub)
    priv_charge = charger_cle_privee(chemin_priv)

    assert pub_charge["n"] == cles_512["publique"]["n"]
    assert pub_charge["e"] == cles_512["publique"]["e"]
    assert priv_charge["d"] == cles_512["privee"]["d"]

def test_serialisation_roundtrip(tmp_path, cles_512):
    """Les clés chargées doivent fonctionner pour chiffrer/déchiffrer."""
    chemin_pub  = str(tmp_path / "pub.json")
    chemin_priv = str(tmp_path / "priv.json")
    sauvegarder_cles(cles_512, chemin_pub, chemin_priv)

    pub  = charger_cle_publique(chemin_pub)
    priv = charger_cle_privee(chemin_priv)

    message = b"test serialisation"
    assert dechiffrer_rsa(chiffrer_rsa(message, pub), priv) == message


# ---------------------------------------------------------------------------
# Signature RSA
# ---------------------------------------------------------------------------

def test_signature_valide(cles_512):
    pub, priv = cles_512["publique"], cles_512["privee"]
    message   = b"Document important"
    sig       = signer_rsa(message, priv)
    assert verifier_signature_rsa(message, sig, pub)

def test_signature_message_modifie_rejete(cles_512):
    pub, priv = cles_512["publique"], cles_512["privee"]
    sig = signer_rsa(b"message original", priv)
    assert not verifier_signature_rsa(b"message modifie", sig, pub)

def test_signature_mauvaise_cle_rejetee(cles_512):
    _, priv = cles_512["publique"], cles_512["privee"]
    pub2    = generer_cles_rsa(bits=256)["publique"]
    sig     = signer_rsa(b"test", priv)
    assert not verifier_signature_rsa(b"test", sig, pub2)

def test_signature_non_deterministe(cles_512):
    """Deux signatures du même message doivent être identiques (sign-the-hash)."""
    pub, priv = cles_512["publique"], cles_512["privee"]
    message   = b"meme message"
    # Notre schéma est déterministe (hash fixe), les deux sigs doivent être égales
    sig1 = signer_rsa(message, priv)
    sig2 = signer_rsa(message, priv)
    assert sig1 == sig2


# ---------------------------------------------------------------------------
# Chiffrement hybride
# ---------------------------------------------------------------------------

def test_hybride_aller_retour(cles_512):
    pub, priv = cles_512["publique"], cles_512["privee"]
    donnees   = b"Fichier confidentiel " * 100
    paquet    = chiffrer_fichier_hybride(donnees, pub)
    recupere  = dechiffrer_fichier_hybride(paquet, priv)
    assert recupere == donnees

def test_hybride_paquet_contient_champs(cles_512):
    pub    = cles_512["publique"]
    paquet = chiffrer_fichier_hybride(b"test", pub)
    assert "cle_session_chiffree" in paquet
    assert "nonce" in paquet
    assert "chiffre" in paquet


# ---------------------------------------------------------------------------
# Attaques (lab/)
# ---------------------------------------------------------------------------

def test_attaque_factorisation_64bits():
    res = attaque_factorisation_64bits()
    assert res["succes"], "Pollard-rho n'a pas réussi à factoriser un module 64 bits"
    assert res["cles_egales"], "La clé privée retrouvée ne correspond pas"

def test_attaque_malleabilite(cles_cours):
    n, e = cles_cours["publique"]["n"], cles_cours["publique"]["e"]
    M = 42
    C = rsa_chiffrer_brut(M, n, e)
    res = attaque_malleabilite(n, e, C)
    # Vérifier que C_modifie déchiffre bien en facteur*M
    d   = cles_cours["privee"]["d"]
    M_prime = rsa_dechiffrer_brut(res["C_modifie"], d, n)
    assert M_prime == res["facteur"] * M

def test_attaque_petite_racine():
    M = 9876
    C = M ** 3
    res = attaque_petite_racine(C, e=3)
    assert res["correct"]
    assert res["M_retrouve"] == M

def test_attaque_facteur_commun():
    res = demo_facteur_commun()
    assert res["succes"]
    assert res["p_commun"] > 1
    assert res["d1"] is not None
    assert res["d2"] is not None

def test_attaque_facteur_commun_modules_disjoints():
    """Deux modules sans facteur commun : l'attaque doit échouer."""
    from cryptolib.numtheory import generate_prime
    p1, _ = generate_prime(32)
    q1, _ = generate_prime(32)
    p2, _ = generate_prime(32)
    q2, _ = generate_prime(32)
    # Assurer qu'ils sont distincts
    while p2 == p1 or p2 == q1:
        p2, _ = generate_prime(32)
    while q2 == p1 or q2 == q1 or q2 == p2:
        q2, _ = generate_prime(32)
    n1 = p1 * q1
    n2 = p2 * q2
    res = attaque_facteur_commun(n1, n2)
    assert not res["succes"]
