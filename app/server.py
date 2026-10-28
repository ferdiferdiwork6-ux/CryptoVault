"""
CryptoVault — Serveur de messagerie sécurisée.
Protocole TLS simplifié :
  1. Inscription   : génération de clés ECC, certificat PKI, stockage mot de passe
  2. Handshake     : ECDHE + signatures mutuelles + dérivation HKDF
  3. Messages      : AES-GCM avec numéros de séquence (anti-rejeu)
  4. Confidentialité persistante : clés éphémères nouvelles à chaque session
"""
from __future__ import annotations
import os
import json
import hashlib
from cryptolib.hashing import hacher_mot_de_passe, verifier_mot_de_passe
from cryptolib.pki import AutoriteCertification, verifier_chaine
from cryptolib.ecc import P256, ecdh_generer_cle, ecdsa_signer, ecdsa_verifier
from cryptolib.dh import hkdf
from cryptolib.symmetric import aes_gcm_chiffrer, aes_gcm_dechiffrer
from cryptolib.prng import HMAC_DRBG


# ---------------------------------------------------------------------------
# Autorité de certification du serveur
# ---------------------------------------------------------------------------

class ServeurCryptoVault:
    """
    Serveur central : gère les utilisateurs, les certificats et les sessions.
    En production ce serait un vrai serveur réseau ; ici c'est une simulation
    en mémoire pour l'intégration pédagogique.
    """

    def __init__(self):
        # PKI interne
        self.ac_racine  = AutoriteCertification("CryptoVault-Root", cle_bits=512)
        self.cert_racine = self.ac_racine.creer_cert_racine()
        self.ac_inter   = AutoriteCertification("CryptoVault-CA", cle_bits=512)
        cert_inter = self.ac_racine.emettre_certificat(
            "CN=CryptoVault-CA", self.ac_inter.cle_pub,
            usage=[], est_ca=True
        )
        self.ac_inter.cert_propre = cert_inter
        self.cert_inter = cert_inter

        # Clé et certificat du serveur (pour l'authentification du serveur)
        self._cle_serveur = ecdh_generer_cle(P256)
        d_srv, Q_srv = self._cle_serveur
        cert_srv = self.ac_inter.emettre_certificat(
            "CN=CryptoVault-Server",
            {"n": Q_srv.x, "e": Q_srv.y},   # clé ECC encodée comme RSA-like
            usage=["signature", "chiffrement"]
        )
        self.cert_serveur = cert_srv
        self._d_serveur   = d_srv

        # Stockage : {username: {hash_mdp, cert, crl}}
        self._utilisateurs: dict[str, dict] = {}
        self._crl: dict = self.ac_inter.publier_crl()
        self._drbg = HMAC_DRBG()

    # --- Inscription ---

    def inscrire(self, username: str, mot_de_passe: str, cle_pub_ecc: dict) -> dict:
        """
        Inscrit un utilisateur :
        - stocke le haché salé du mot de passe
        - émet un certificat signé par l'AC intermédiaire
        Retourne le certificat utilisateur.
        """
        if username in self._utilisateurs:
            raise ValueError(f"Utilisateur '{username}' déjà inscrit.")

        hash_mdp, _ = hacher_mot_de_passe(mot_de_passe, iterations=50_000)

        cert_user = self.ac_inter.emettre_certificat(
            f"CN={username}",
            cle_pub_ecc,
            usage=["signature", "chiffrement"],
        )

        self._utilisateurs[username] = {
            "hash_mdp": hash_mdp,
            "cert":     cert_user,
        }
        return cert_user

    def authentifier(self, username: str, mot_de_passe: str) -> bool:
        """Vérifie le mot de passe d'un utilisateur."""
        if username not in self._utilisateurs:
            return False
        return verifier_mot_de_passe(mot_de_passe, self._utilisateurs[username]["hash_mdp"])

    def obtenir_cert(self, username: str) -> dict | None:
        """Retourne le certificat d'un utilisateur."""
        info = self._utilisateurs.get(username)
        return info["cert"] if info else None

    # --- Handshake ECDHE ---

    def handshake_initier(self) -> dict:
        """
        Étape serveur du handshake :
        - génère une paire ECDHE éphémère
        - signe la valeur publique avec sa clé longue terme
        Retourne la part publique éphémère + signature + certificat serveur.
        """
        d_eph, Q_eph = ecdh_generer_cle(P256)
        self._eph_courant = (d_eph, Q_eph)
        nb = (P256.p.bit_length() + 7) // 8

        # Signer Q_eph avec la clé longue terme du serveur
        payload = Q_eph.x.to_bytes(nb, "big") + Q_eph.y.to_bytes(nb, "big")
        sig = ecdsa_signer(payload, self._d_serveur, P256)

        return {
            "Q_eph_x":    Q_eph.x,
            "Q_eph_y":    Q_eph.y,
            "signature":  sig,
            "cert_srv":   self.cert_serveur,
            "cert_inter": self.cert_inter,
            "cert_racine": self.cert_racine,
        }

    def handshake_finaliser(
        self,
        Q_client_x: int,
        Q_client_y: int,
        sig_client: tuple,
        cert_client: dict,
    ) -> dict | None:
        """
        Finalise le handshake côté serveur :
        - vérifie la signature du client sur sa part ECDHE
        - vérifie le certificat du client
        - calcule le secret partagé et dérive les clés
        """
        from cryptolib.ecc import Point, ecdh_secret_partage, ecdsa_verifier

        # Vérifier le certificat du client
        ok, _ = verifier_chaine(cert_client, [self.cert_inter], self.cert_racine)
        if not ok:
            return None

        # Vérifier la signature du client sur sa part ECDHE
        nb = (P256.p.bit_length() + 7) // 8
        payload = Q_client_x.to_bytes(nb, "big") + Q_client_y.to_bytes(nb, "big")
        cle_pub_client = {
            k: int(v, 16) for k, v in cert_client["cle_publique"].items()
        }
        # Reconstruction du point ECC depuis le certificat
        Q_lt = Point(cle_pub_client["n"], cle_pub_client["e"])
        if not ecdsa_verifier(payload, sig_client, Q_lt, P256):
            return None

        # Calcul du secret partagé ECDHE
        d_eph, _ = self._eph_courant
        Q_client = Point(Q_client_x, Q_client_y)
        secret   = ecdh_secret_partage(d_eph, Q_client, P256)

        # Dérivation HKDF → deux clés symétriques
        cle_enc  = hkdf(secret, 32, info=b"cryptovault-enc")
        cle_auth = hkdf(secret, 32, info=b"cryptovault-auth")

        del self._eph_courant   # effacer la clé éphémère (PFS)

        return {"cle_enc": cle_enc, "cle_auth": cle_auth}

    # --- Transmission de messages ---

    def chiffrer_message(
        self,
        message: bytes,
        cle_enc: bytes,
        seq: int,
    ) -> dict:
        """Chiffre un message avec numéro de séquence anti-rejeu."""
        nonce   = seq.to_bytes(4, "big") + os.urandom(8)
        chiffre, tag = aes_gcm_chiffrer(cle_enc, nonce, message,
                                         aad=seq.to_bytes(8, "big"))
        return {"seq": seq, "nonce": nonce.hex(), "chiffre": chiffre.hex(), "tag": tag.hex()}

    def dechiffrer_message(
        self,
        paquet: dict,
        cle_enc: bytes,
        seq_attendu: int,
    ) -> bytes:
        """Déchiffre et vérifie le numéro de séquence."""
        if paquet["seq"] != seq_attendu:
            raise ValueError(f"Rejeu détecté : seq={paquet['seq']}, attendu={seq_attendu}")
        nonce   = bytes.fromhex(paquet["nonce"])
        chiffre = bytes.fromhex(paquet["chiffre"])
        tag     = bytes.fromhex(paquet["tag"])
        return aes_gcm_dechiffrer(cle_enc, nonce, chiffre, tag,
                                   aad=paquet["seq"].to_bytes(8, "big"))
