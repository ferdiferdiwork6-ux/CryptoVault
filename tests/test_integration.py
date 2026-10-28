"""Tests integration module 9."""
from __future__ import annotations
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from app.server import ServeurCryptoVault
from app.client import ClientCryptoVault
from app.vault  import CoffreFort
from cryptolib.rsa import generer_cles_rsa
from cryptolib.ecc import P256, ecdh_generer_cle

@pytest.fixture(scope="module")
def srv():
    return ServeurCryptoVault()

@pytest.fixture(scope="module")
def alice(srv):
    c = ClientCryptoVault("alice")
    c.generer_identite("mdp_alice", srv)
    return c

@pytest.fixture(scope="module")
def bob(srv):
    c = ClientCryptoVault("bob")
    c.generer_identite("mdp_bob", srv)
    return c

@pytest.fixture(scope="module")
def cles_alice():
    return generer_cles_rsa(bits=512)

@pytest.fixture(scope="module")
def cles_bob():
    return generer_cles_rsa(bits=512)

@pytest.fixture(scope="module")
def ecc_alice():
    d, Q = ecdh_generer_cle(P256)
    return {"d": d, "Q": Q}

@pytest.fixture(scope="module")
def coffre():
    return CoffreFort()

# Inscription
def test_inscription_alice(srv, alice):
    assert srv.obtenir_cert("alice") is not None

def test_inscription_double_erreur(srv, alice):
    with pytest.raises(ValueError):
        ClientCryptoVault("alice").generer_identite("x", srv)

def test_auth_correcte(srv, alice):
    assert srv.authentifier("alice", "mdp_alice")

def test_auth_mauvais_mdp(srv, alice):
    assert not srv.authentifier("alice", "mauvais")

def test_cert_alice(srv, alice):
    cert = srv.obtenir_cert("alice")
    assert cert["sujet"] == "CN=alice"
    assert "signature" in cert

# Handshake
def test_handshake_ok(alice, srv):
    cles = alice.handshake(srv)
    assert len(cles["cle_enc"]) == 32
    assert len(cles["cle_auth"]) == 32

def test_pfs_cles_differentes(alice, srv):
    c1 = alice.handshake(srv)
    c2 = alice.handshake(srv)
    assert c1["cle_enc"] != c2["cle_enc"]

def test_handshake_bob(bob, srv):
    cles = bob.handshake(srv)
    assert len(cles["cle_enc"]) == 32

# Messages
def test_envoi_reception(alice, srv):
    alice.handshake(srv)
    msg = b"Bonjour CryptoVault"
    p = alice.envoyer(msg, srv)
    assert alice.recevoir(p, srv) == msg

def test_sequence_messages(alice, srv):
    alice.handshake(srv)
    msgs = [b"msg1", b"msg2 longer", b"msg3" * 10]
    paquets = [alice.envoyer(m, srv) for m in msgs]
    for m, p in zip(msgs, paquets):
        assert alice.recevoir(p, srv) == m

def test_anti_rejeu(alice, srv):
    alice.handshake(srv)
    p = alice.envoyer(b"test", srv)
    p_bad = dict(p)
    p_bad["seq"] = 999
    with pytest.raises(ValueError):
        srv.dechiffrer_message(p_bad, alice._cle_enc, 0)

def test_clair_absent_du_chiffre(alice, srv):
    alice.handshake(srv)
    msg = b"SECRET"
    p = alice.envoyer(msg, srv)
    assert msg not in bytes.fromhex(p["chiffre"])

def test_corruption_detectee(alice, srv):
    alice.handshake(srv)
    p = alice.envoyer(b"test", srv)
    pc = dict(p)
    c = bytes.fromhex(p["chiffre"])
    pc["chiffre"] = (bytes([c[0]^0xFF]) + c[1:]).hex()
    with pytest.raises(Exception):
        alice.recevoir(pc, srv)

# Coffre-fort
def test_add_get(coffre, cles_alice, ecc_alice):
    data = b"Donnees confidentielles"
    coffre.ajouter("f1.txt", data, ecc_alice["d"], [cles_alice["publique"]])
    assert coffre.obtenir("f1.txt", cles_alice["privee"], ecc_alice["Q"]) == data

def test_list(coffre, cles_alice, ecc_alice):
    coffre.ajouter("f2.txt", b"data2", ecc_alice["d"], [cles_alice["publique"]])
    assert "f2.txt" in coffre.lister()

def test_mauvaise_cle_rejetee(coffre, cles_alice, cles_bob, ecc_alice):
    coffre.ajouter("fprive.txt", b"secret", ecc_alice["d"], [cles_alice["publique"]])
    with pytest.raises(Exception):
        coffre.obtenir("fprive.txt", cles_bob["privee"], ecc_alice["Q"])

def test_signature_invalide(coffre, cles_alice, ecc_alice):
    coffre.ajouter("fsign.txt", b"data", ecc_alice["d"], [cles_alice["publique"]])
    _, Q2 = ecdh_generer_cle(P256)
    with pytest.raises(ValueError):
        coffre.obtenir("fsign.txt", cles_alice["privee"], Q2)

def test_share(coffre, cles_alice, cles_bob, ecc_alice):
    data = b"partage"
    coffre.ajouter("fshare.txt", data, ecc_alice["d"], [cles_alice["publique"]])
    coffre.partager("fshare.txt", cles_alice["privee"], [cles_bob["publique"]])
    assert coffre.obtenir("fshare.txt", cles_bob["privee"], ecc_alice["Q"]) == data

def test_merkle(coffre, cles_alice, ecc_alice):
    from cryptolib.hashing import verifier_preuve_merkle
    coffre.ajouter("fmerkle.bin", b"Y"*3000, ecc_alice["d"], [cles_alice["publique"]])
    pi = coffre.prouver_bloc("fmerkle.bin", 0)
    bloc   = bytes.fromhex(pi["bloc"])
    preuve = [(d, bytes.fromhex(h)) for d, h in pi["preuve"]]
    racine = bytes.fromhex(pi["racine"])
    assert verifier_preuve_merkle(bloc, 0, preuve, racine)

def test_gros_fichier(coffre, cles_alice, ecc_alice):
    data = os.urandom(50_000)
    coffre.ajouter("big.bin", data, ecc_alice["d"], [cles_alice["publique"]])
    assert coffre.obtenir("big.bin", cles_alice["privee"], ecc_alice["Q"]) == data

# Tracabilite
def test_tous_modules_importables():
    import cryptolib.hashing, cryptolib.numtheory, cryptolib.rsa
    import cryptolib.dh, cryptolib.ecc, cryptolib.symmetric
    import cryptolib.pki, cryptolib.prng

def test_racine_merkle_hex(coffre, cles_alice, ecc_alice):
    racine = coffre.ajouter("trace.txt", b"trace", ecc_alice["d"], [cles_alice["publique"]])
    assert len(racine) == 64
