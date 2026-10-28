"""
CryptoVault — Coffre-fort de fichiers chiffrés.
Commandes : add, get, list, share
- Chaque fichier est chiffré par une clé de fichier AES-GCM aléatoire
- La clé de fichier est chiffrée pour chaque destinataire autorisé (RSA-OAEP)
- Un arbre de Merkle vérifie l'intégrité par blocs
- L'auteur signe le fichier avec sa clé privée ECC
"""
from __future__ import annotations
import os
import json
import hashlib
from cryptolib.symmetric import aes_gcm_chiffrer, aes_gcm_dechiffrer
from cryptolib.rsa import chiffrer_rsa, dechiffrer_rsa
from cryptolib.ecc import P256, ecdsa_signer, ecdsa_verifier, Point
from cryptolib.hashing import racine_merkle, preuve_merkle, verifier_preuve_merkle
from cryptolib.prng import HMAC_DRBG

_TAILLE_BLOC_MERKLE = 1024   # octets par bloc pour l'arbre de Merkle
_drbg = HMAC_DRBG()


class CoffreFort:
    """
    Coffre-fort en mémoire (dict).
    En production, ce serait une base de données chiffrée sur disque.
    """

    def __init__(self):
        # {nom_fichier: {chiffre, nonce, tag, cles_chiffrees, merkle_racine, signature}}
        self._entrees: dict[str, dict] = {}

    # --- Chiffrement et ajout ---

    def ajouter(
        self,
        nom: str,
        donnees: bytes,
        auteur_d: int,           # clé privée ECC de l'auteur
        destinataires_rsa: list[dict],   # liste de clés publiques RSA des destinataires
    ) -> str:
        """
        Chiffre donnees avec AES-GCM (clé aléatoire),
        chiffre la clé de session pour chaque destinataire,
        construit l'arbre de Merkle et signe.
        Retourne la racine de Merkle.
        """
        # 1. Clé de fichier AES-256 aléatoire
        cle_fichier = _drbg.generer_octets(32)
        nonce       = _drbg.generer_octets(12)

        # 2. Chiffrement AES-GCM
        chiffre, tag = aes_gcm_chiffrer(cle_fichier, nonce, donnees)

        # 3. Chiffrer la clé de fichier pour chaque destinataire (RSA-OAEP)
        cles_chiffrees = {}
        for cle_pub in destinataires_rsa:
            identifiant = hashlib.sha256(
                str(cle_pub["n"]).encode()
            ).hexdigest()[:16]
            cles_chiffrees[identifiant] = chiffrer_rsa(cle_fichier, cle_pub).hex()

        # 4. Arbre de Merkle sur les blocs du fichier chiffré
        blocs = [chiffre[i:i+_TAILLE_BLOC_MERKLE]
                 for i in range(0, len(chiffre), _TAILLE_BLOC_MERKLE)] or [b""]
        racine = racine_merkle(blocs)

        # 5. Signature ECC de l'auteur sur la racine de Merkle
        sig = ecdsa_signer(racine, auteur_d, P256)

        self._entrees[nom] = {
            "chiffre":        chiffre.hex(),
            "nonce":          nonce.hex(),
            "tag":            tag.hex(),
            "cles_chiffrees": cles_chiffrees,
            "merkle_racine":  racine.hex(),
            "signature":      sig,
            "nb_blocs":       len(blocs),
        }
        return racine.hex()

    # --- Déchiffrement ---

    def obtenir(
        self,
        nom: str,
        cle_priv_rsa: dict,     # clé privée RSA du destinataire
        auteur_Q: Point,        # clé publique ECC de l'auteur (pour vérif signature)
        verifier_integrite: bool = True,
    ) -> bytes:
        """
        Déchiffre un fichier du coffre-fort.
        Vérifie la signature et l'intégrité Merkle avant de retourner les données.
        """
        if nom not in self._entrees:
            raise KeyError(f"Fichier '{nom}' introuvable dans le coffre.")

        entree = self._entrees[nom]

        # 1. Vérifier la signature de l'auteur sur la racine de Merkle
        racine  = bytes.fromhex(entree["merkle_racine"])
        sig     = entree["signature"]
        if not ecdsa_verifier(racine, sig, auteur_Q, P256):
            raise ValueError("Signature de l'auteur invalide : fichier corrompu ou falsifié.")

        # 2. Retrouver la clé de fichier chiffrée pour ce destinataire
        identifiant = hashlib.sha256(
            str(cle_priv_rsa["p"] * cle_priv_rsa["q"]).encode()
        ).hexdigest()[:16]

        if identifiant not in entree["cles_chiffrees"]:
            raise PermissionError("Vous n'êtes pas destinataire autorisé de ce fichier.")

        cle_fichier = dechiffrer_rsa(
            bytes.fromhex(entree["cles_chiffrees"][identifiant]),
            cle_priv_rsa,
        )

        # 3. Déchiffrer AES-GCM
        nonce   = bytes.fromhex(entree["nonce"])
        chiffre = bytes.fromhex(entree["chiffre"])
        tag     = bytes.fromhex(entree["tag"])
        donnees = aes_gcm_dechiffrer(cle_fichier, nonce, chiffre, tag)

        # 4. Vérifier l'intégrité Merkle
        if verifier_integrite:
            blocs  = [chiffre[i:i+_TAILLE_BLOC_MERKLE]
                      for i in range(0, len(chiffre), _TAILLE_BLOC_MERKLE)] or [b""]
            racine_calculee = racine_merkle(blocs)
            if racine_calculee != racine:
                raise ValueError("Intégrité Merkle échouée : fichier corrompu.")

        return donnees

    # --- Partage ---

    def partager(
        self,
        nom: str,
        cle_priv_rsa_proprietaire: dict,
        nouvelles_cles_pub_rsa: list[dict],
    ) -> None:
        """
        Ajoute de nouveaux destinataires à un fichier existant.
        Le propriétaire déchiffre la clé de fichier et la rechiffre pour les nouveaux.
        """
        if nom not in self._entrees:
            raise KeyError(f"Fichier '{nom}' introuvable.")

        entree = self._entrees[nom]
        identifiant_proprio = hashlib.sha256(
            str(cle_priv_rsa_proprietaire["p"] * cle_priv_rsa_proprietaire["q"]).encode()
        ).hexdigest()[:16]

        if identifiant_proprio not in entree["cles_chiffrees"]:
            raise PermissionError("Seul un destinataire autorisé peut partager.")

        cle_fichier = dechiffrer_rsa(
            bytes.fromhex(entree["cles_chiffrees"][identifiant_proprio]),
            cle_priv_rsa_proprietaire,
        )

        for cle_pub in nouvelles_cles_pub_rsa:
            ident = hashlib.sha256(str(cle_pub["n"]).encode()).hexdigest()[:16]
            entree["cles_chiffrees"][ident] = chiffrer_rsa(cle_fichier, cle_pub).hex()

    # --- Listage ---

    def lister(self) -> list[str]:
        return list(self._entrees.keys())

    # --- Preuve d'appartenance d'un bloc ---

    def prouver_bloc(self, nom: str, index_bloc: int) -> dict:
        """Génère une preuve de Merkle pour le bloc donné."""
        if nom not in self._entrees:
            raise KeyError(f"Fichier '{nom}' introuvable.")
        entree  = self._entrees[nom]
        chiffre = bytes.fromhex(entree["chiffre"])
        blocs   = [chiffre[i:i+_TAILLE_BLOC_MERKLE]
                   for i in range(0, len(chiffre), _TAILLE_BLOC_MERKLE)] or [b""]
        preuve  = preuve_merkle(blocs, index_bloc)
        return {
            "bloc":    blocs[index_bloc].hex(),
            "index":   index_bloc,
            "preuve":  [(d, h.hex()) for d, h in preuve],
            "racine":  entree["merkle_racine"],
        }
