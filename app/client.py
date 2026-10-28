"""
CryptoVault — Client de messagerie sécurisée.
"""
from __future__ import annotations
import os
from cryptolib.ecc import P256, ecdh_generer_cle, ecdsa_signer, ecdsa_verifier, Point
from cryptolib.dh import hkdf
from cryptolib.symmetric import aes_gcm_chiffrer, aes_gcm_dechiffrer
from cryptolib.pki import keystore_creer, keystore_charger, verifier_chaine


class ClientCryptoVault:
    """Client qui s'inscrit, s'authentifie et échange des messages chiffrés."""

    def __init__(self, username: str):
        self.username    = username
        self._d_lt: int | None  = None   # clé privée longue terme ECC
        self._Q_lt: object | None = None
        self._cert: dict | None  = None
        self._keystore: dict | None = None
        self._seq_envoi  = 0
        self._seq_recept = 0

    # --- Inscription ---

    def generer_identite(self, mot_de_passe: str, serveur) -> dict:
        """
        Génère les clés ECC, s'inscrit auprès du serveur, stocke dans un keystore.
        Retourne le certificat émis.
        """
        self._d_lt, self._Q_lt = ecdh_generer_cle(P256)
        cle_pub_dict = {"n": self._Q_lt.x, "e": self._Q_lt.y}

        self._cert = serveur.inscrire(self.username, mot_de_passe, cle_pub_dict)
        # Stocker la clé privée chiffrée (keystore)
        self._keystore = keystore_creer(
            {"d": self._d_lt, "p": 0, "q": 0, "dp": 0, "dq": 0, "qinv": 0},
            mot_de_passe,
        )
        return self._cert

    def charger_identite(self, keystore: dict, mot_de_passe: str, cert: dict) -> None:
        """Charge une identité depuis un keystore protégé."""
        priv = keystore_charger(keystore, mot_de_passe)
        self._d_lt  = priv["d"]
        self._cert  = cert

    # --- Handshake ECDHE côté client ---

    def handshake(self, serveur) -> dict:
        """
        Effectue le handshake avec le serveur :
        1. Reçoit la part éphémère du serveur + signature + certificats
        2. Vérifie tout
        3. Envoie sa propre part éphémère signée
        4. Dérive les clés de session
        Retourne {"cle_enc": ..., "cle_auth": ...} ou lève une exception.
        """
        # --- Étape 1 : recevoir la part serveur ---
        rep = serveur.handshake_initier()
        Q_srv_eph = Point(rep["Q_eph_x"], rep["Q_eph_y"])

        # Vérifier la chaîne de certificats du serveur
        ok, raison = verifier_chaine(
            rep["cert_srv"], [rep["cert_inter"]], rep["cert_racine"]
        )
        if not ok:
            raise ValueError(f"Certificat serveur invalide : {raison}")

        # Vérifier la signature du serveur sur Q_eph
        nb = (P256.p.bit_length() + 7) // 8
        payload_srv = rep["Q_eph_x"].to_bytes(nb, "big") + rep["Q_eph_y"].to_bytes(nb, "big")
        cle_pub_srv = {k: int(v, 16) for k, v in rep["cert_srv"]["cle_publique"].items()}
        Q_srv_lt = Point(cle_pub_srv["n"], cle_pub_srv["e"])
        if not ecdsa_verifier(payload_srv, rep["signature"], Q_srv_lt, P256):
            raise ValueError("Signature du serveur invalide sur la part ECDHE")

        # --- Étape 2 : générer et envoyer la part éphémère du client ---
        d_eph, Q_eph = ecdh_generer_cle(P256)
        payload_cli = Q_eph.x.to_bytes(nb, "big") + Q_eph.y.to_bytes(nb, "big")
        sig_cli = ecdsa_signer(payload_cli, self._d_lt, P256)

        # --- Étape 3 : finaliser côté serveur ---
        cles = serveur.handshake_finaliser(
            Q_eph.x, Q_eph.y, sig_cli, self._cert
        )
        if cles is None:
            raise ValueError("Handshake rejeté par le serveur")

        # --- Étape 4 : calculer le secret partagé côté client ---
        from cryptolib.ecc import ecdh_secret_partage
        secret  = ecdh_secret_partage(d_eph, Q_srv_eph, P256)
        cle_enc  = hkdf(secret, 32, info=b"cryptovault-enc")
        cle_auth = hkdf(secret, 32, info=b"cryptovault-auth")

        del d_eph   # PFS : effacer la clé éphémère

        # Vérifier que les deux parties ont le même secret
        assert cle_enc == cles["cle_enc"], "Désaccord sur la clé de session !"

        self._cle_enc  = cle_enc
        self._cle_auth = cle_auth
        self._seq_envoi  = 0
        self._seq_recept = 0
        return {"cle_enc": cle_enc, "cle_auth": cle_auth}

    # --- Envoi / réception ---

    def envoyer(self, message: bytes, serveur) -> dict:
        paquet = serveur.chiffrer_message(message, self._cle_enc, self._seq_envoi)
        self._seq_envoi += 1
        return paquet

    def recevoir(self, paquet: dict, serveur) -> bytes:
        clair = serveur.dechiffrer_message(paquet, self._cle_enc, self._seq_recept)
        self._seq_recept += 1
        return clair
