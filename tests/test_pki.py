"""
Tests unitaires pour cryptolib/pki.py
"""
from __future__ import annotations
import sys, os, time, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from cryptolib.rsa import generer_cles_rsa
from cryptolib.pki import (
    AutoriteCertification,
    verifier_certificat,
    verifier_chaine,
    keystore_creer, keystore_charger, keystore_changer_mdp,
    demo_pki,
    _corps_cert,
)


# ---------------------------------------------------------------------------
# Fixture : hiérarchie PKI complète
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def pki():
    """Crée racine → intermédiaire → certificat Alice (clés 512 bits)."""
    ac_racine = AutoriteCertification("RacineCA", cle_bits=512)
    cert_racine = ac_racine.creer_cert_racine()

    ac_inter = AutoriteCertification("InterCA", cle_bits=512)
    cert_inter = ac_racine.emettre_certificat(
        "CN=InterCA", ac_inter.cle_pub, usage=[], est_ca=True
    )
    ac_inter.cert_propre = cert_inter

    cles_alice = generer_cles_rsa(bits=512)
    cert_alice = ac_inter.emettre_certificat(
        "CN=Alice", cles_alice["publique"], usage=["signature"]
    )

    return {
        "ac_racine":    ac_racine,
        "cert_racine":  cert_racine,
        "ac_inter":     ac_inter,
        "cert_inter":   cert_inter,
        "cles_alice":   cles_alice,
        "cert_alice":   cert_alice,
    }


# ---------------------------------------------------------------------------
# Certificat racine
# ---------------------------------------------------------------------------

def test_cert_racine_auto_signe(pki):
    cert = pki["cert_racine"]
    assert cert["sujet"] == cert["emetteur"]
    assert "ca" in cert["usage"]

def test_cert_racine_champs_presents(pki):
    cert = pki["cert_racine"]
    for champ in ["version", "serie", "sujet", "emetteur",
                  "not_before", "not_after", "cle_publique", "usage", "signature"]:
        assert champ in cert, f"Champ manquant : {champ}"

def test_cert_racine_serie_unique(pki):
    """Deux certificats racine générés ont des numéros de série distincts."""
    ac2 = AutoriteCertification("RacineCA2", cle_bits=512)
    c2  = ac2.creer_cert_racine()
    assert pki["cert_racine"]["serie"] != c2["serie"]

def test_cert_racine_validite_temporelle(pki):
    now = int(time.time())
    cert = pki["cert_racine"]
    assert cert["not_before"] <= now <= cert["not_after"]


# ---------------------------------------------------------------------------
# Émission de certificats
# ---------------------------------------------------------------------------

def test_cert_intermediaire_emetteur(pki):
    assert pki["cert_inter"]["emetteur"] == f"CN={pki['ac_racine'].nom}"

def test_cert_intermediaire_est_ca(pki):
    assert "ca" in pki["cert_inter"]["usage"]

def test_cert_alice_sujet(pki):
    assert pki["cert_alice"]["sujet"] == "CN=Alice"

def test_cert_alice_non_ca(pki):
    assert "ca" not in pki["cert_alice"].get("usage", [])

def test_cert_sans_cert_propre_leve_erreur():
    ac = AutoriteCertification("Test", cle_bits=512)
    cles = generer_cles_rsa(bits=512)
    with pytest.raises(RuntimeError):
        ac.emettre_certificat("CN=Bob", cles["publique"], usage=[])


# ---------------------------------------------------------------------------
# Vérification d'un certificat unique
# ---------------------------------------------------------------------------

def test_verifier_cert_valide(pki):
    ok, raison = verifier_certificat(
        pki["cert_inter"], pki["cert_racine"]
    )
    assert ok, raison

def test_verifier_cert_alice(pki):
    ok, raison = verifier_certificat(
        pki["cert_alice"], pki["cert_inter"]
    )
    assert ok, raison

def test_verifier_cert_signature_falsifiee(pki):
    cert = dict(pki["cert_alice"])
    cert["sujet"] = "CN=Mallory"   # modifier le corps sans re-signer
    ok, raison = verifier_certificat(cert, pki["cert_inter"])
    assert not ok
    assert "Signature" in raison

def test_verifier_cert_expire(pki):
    ac = pki["ac_inter"]
    cles = generer_cles_rsa(bits=512)
    cert = ac.emettre_certificat("CN=Expire", cles["publique"], usage=[], duree_jours=1)
    # Simuler un timestamp dans le futur (certificat expiré)
    ok, raison = verifier_certificat(
        cert, pki["cert_inter"],
        maintenant=int(time.time()) + 2 * 86400   # +2 jours
    )
    assert not ok
    assert "expir" in raison.lower()

def test_verifier_cert_pas_encore_valide(pki):
    ac = pki["ac_inter"]
    cles = generer_cles_rsa(bits=512)
    cert = ac.emettre_certificat("CN=Future", cles["publique"], usage=[])
    ok, raison = verifier_certificat(
        cert, pki["cert_inter"],
        maintenant=cert["not_before"] - 1   # avant la date de début
    )
    assert not ok
    assert "valide" in raison.lower()

def test_verifier_cert_emetteur_non_ca(pki):
    """Un certificat feuille ne peut pas signer d'autres certificats.
    La vérification échoue soit sur la signature soit sur le flag CA."""
    cles_bob = generer_cles_rsa(bits=512)
    cert_faux = pki["ac_inter"].emettre_certificat(
        "CN=Bob", cles_bob["publique"], usage=[]
    )
    # cert_alice est passé comme émetteur : sa clé ne correspond pas à la signature
    ok, raison = verifier_certificat(cert_faux, pki["cert_alice"])
    assert not ok   # doit échouer (signature ou flag CA)


# ---------------------------------------------------------------------------
# Vérification de chaîne
# ---------------------------------------------------------------------------

def test_chaine_valide(pki):
    ok, raison = verifier_chaine(
        pki["cert_alice"],
        [pki["cert_inter"]],
        pki["cert_racine"],
    )
    assert ok, raison

def test_chaine_cert_falsifie_rejete(pki):
    cert_faux = dict(pki["cert_alice"])
    cert_faux["sujet"] = "CN=Pirate"
    ok, _ = verifier_chaine(cert_faux, [pki["cert_inter"]], pki["cert_racine"])
    assert not ok

def test_chaine_racine_inconnue_rejetee(pki):
    """Une racine différente ne doit pas valider la chaîne."""
    ac_autre = AutoriteCertification("AutreCA", cle_bits=512)
    cert_autre_racine = ac_autre.creer_cert_racine()
    ok, _ = verifier_chaine(
        pki["cert_alice"], [pki["cert_inter"]], cert_autre_racine
    )
    assert not ok


# ---------------------------------------------------------------------------
# Révocation (CRL)
# ---------------------------------------------------------------------------

def test_revocation_rejete(pki):
    pki["ac_inter"].revoquer(pki["cert_alice"]["serie"])
    crl = pki["ac_inter"].publier_crl()
    ok, raison = verifier_chaine(
        pki["cert_alice"], [pki["cert_inter"]], pki["cert_racine"], crl=crl
    )
    assert not ok
    assert "révoqué" in raison.lower() or "revoque" in raison.lower()

def test_crl_signee(pki):
    """La CRL doit être signée par l'AC intermédiaire."""
    from cryptolib.rsa import verifier_signature_rsa
    crl = pki["ac_inter"].publier_crl()
    sig = bytes.fromhex(crl["signature"])
    corps = json.dumps(
        {k: v for k, v in crl.items() if k != "signature"}, sort_keys=True
    ).encode()
    assert verifier_signature_rsa(corps, sig, pki["ac_inter"].cle_pub)

def test_cert_non_revoque_accepte(pki):
    """Un certificat non révoqué reste valide même avec une CRL."""
    cles_bob = generer_cles_rsa(bits=512)
    cert_bob = pki["ac_inter"].emettre_certificat(
        "CN=Bob", cles_bob["publique"], usage=[]
    )
    crl = pki["ac_inter"].publier_crl()   # Alice est révoquée, pas Bob
    ok, _ = verifier_chaine(
        cert_bob, [pki["cert_inter"]], pki["cert_racine"], crl=crl
    )
    assert ok


# ---------------------------------------------------------------------------
# Keystore
# ---------------------------------------------------------------------------

def test_keystore_creer_charger():
    cles = generer_cles_rsa(bits=512)
    mdp  = "motdepasse_test"
    ks   = keystore_creer(cles["privee"], mdp)
    priv = keystore_charger(ks, mdp)
    assert priv["d"] == cles["privee"]["d"]

def test_keystore_mauvais_mdp():
    cles = generer_cles_rsa(bits=512)
    ks   = keystore_creer(cles["privee"], "correct")
    with pytest.raises(ValueError):
        keystore_charger(ks, "incorrect")

def test_keystore_changer_mdp():
    cles = generer_cles_rsa(bits=512)
    ks1  = keystore_creer(cles["privee"], "ancien")
    ks2  = keystore_changer_mdp(ks1, "ancien", "nouveau")
    # Ancien mot de passe rejeté
    with pytest.raises(ValueError):
        keystore_charger(ks2, "ancien")
    # Nouveau mot de passe accepté
    priv = keystore_charger(ks2, "nouveau")
    assert priv["d"] == cles["privee"]["d"]

def test_keystore_chiffrement_different_a_chaque_fois():
    """Deux keystores du même secret doivent être différents (sel aléatoire)."""
    cles = generer_cles_rsa(bits=512)
    ks1  = keystore_creer(cles["privee"], "mdp")
    ks2  = keystore_creer(cles["privee"], "mdp")
    assert ks1["chiffre"] != ks2["chiffre"]

def test_keystore_cle_privee_non_en_clair():
    """La clé privée ne doit pas apparaître en clair dans le keystore."""
    cles = generer_cles_rsa(bits=512)
    ks   = keystore_creer(cles["privee"], "mdp")
    ks_str = json.dumps(ks)
    # La valeur de d ne doit pas être dans le JSON du keystore
    assert hex(cles["privee"]["d"]) not in ks_str


# ---------------------------------------------------------------------------
# Scénario complet
# ---------------------------------------------------------------------------

def test_demo_pki():
    res = demo_pki()
    assert res["chaine_valide_avant_revocation"], res["raison_avant"]
    assert not res["chaine_valide_apres_revocation"], "Doit être rejeté après révocation"
    assert res["keystore_ok"]
