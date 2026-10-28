"""
Module 7 : Infrastructure à clés publiques (PKI) simplifiée.
- Certificats JSON signés (format maison, inspiré X.509)
- Hiérarchie : AC racine → AC intermédiaire → certificat feuille
- Révocation (CRL signée)
- Keystore chiffré (clé privée protégée par mot de passe)
"""
from __future__ import annotations
import os
import json
import time
import hashlib
from cryptolib.hashing import hmac_sha256, comparer_temps_constant
from cryptolib.rsa import (
    generer_cles_rsa, signer_rsa, verifier_signature_rsa,
    chiffrer_rsa, dechiffrer_rsa,
)
from cryptolib.symmetric import aes_gcm_chiffrer, aes_gcm_dechiffrer


# ---------------------------------------------------------------------------
# Structure d'un certificat (format JSON maison)
# ---------------------------------------------------------------------------
# {
#   "version": 1,
#   "serie": "hex",
#   "sujet": "CN=...",
#   "emetteur": "CN=...",
#   "not_before": timestamp,
#   "not_after":  timestamp,
#   "cle_publique": {"n": "hex", "e": "hex"},
#   "usage": ["ca" | "signature" | "chiffrement"],
#   "signature": "hex"          <- sur le corps (tous les champs sauf signature)
# }


def _corps_cert(cert: dict) -> bytes:
    """Sérialise le corps du certificat (sans la signature) pour signer/vérifier."""
    corps = {k: v for k, v in cert.items() if k != "signature"}
    return json.dumps(corps, sort_keys=True).encode()


def _nouvelle_serie() -> str:
    return os.urandom(8).hex()


# ---------------------------------------------------------------------------
# Autorité de Certification
# ---------------------------------------------------------------------------

class AutoriteCertification:
    """Mini-AC capable d'émettre, vérifier et révoquer des certificats."""

    def __init__(self, nom: str, cle_bits: int = 512):
        self.nom = nom
        cles = generer_cles_rsa(bits=cle_bits)
        self.cle_pub  = cles["publique"]
        self.cle_priv = cles["privee"]
        self.cert_propre: dict | None = None
        self._crl: list[str] = []   # liste des numéros de série révoqués

    # --- Création du certificat auto-signé (racine) ---

    def creer_cert_racine(self, duree_jours: int = 3650) -> dict:
        """Crée et signe le certificat racine (auto-signé)."""
        now = int(time.time())
        cert = {
            "version":      1,
            "serie":        _nouvelle_serie(),
            "sujet":        f"CN={self.nom}",
            "emetteur":     f"CN={self.nom}",
            "not_before":   now,
            "not_after":    now + duree_jours * 86400,
            "cle_publique": {k: hex(v) for k, v in self.cle_pub.items()},
            "usage":        ["ca"],
        }
        cert["signature"] = signer_rsa(_corps_cert(cert), self.cle_priv).hex()
        self.cert_propre = cert
        return cert

    # --- Émission d'un certificat pour une entité ---

    def emettre_certificat(
        self,
        sujet: str,
        cle_pub_sujet: dict,
        usage: list[str],
        duree_jours: int = 365,
        est_ca: bool = False,
    ) -> dict:
        """Signe et retourne un certificat pour le sujet donné."""
        if self.cert_propre is None:
            raise RuntimeError("L'AC n'a pas encore de certificat propre.")
        now = int(time.time())
        cert = {
            "version":      1,
            "serie":        _nouvelle_serie(),
            "sujet":        sujet,
            "emetteur":     f"CN={self.nom}",
            "not_before":   now,
            "not_after":    now + duree_jours * 86400,
            "cle_publique": {k: hex(v) for k, v in cle_pub_sujet.items()},
            "usage":        usage + (["ca"] if est_ca else []),
        }
        cert["signature"] = signer_rsa(_corps_cert(cert), self.cle_priv).hex()
        return cert

    # --- Révocation ---

    def revoquer(self, serie: str) -> None:
        """Ajoute le numéro de série à la CRL."""
        if serie not in self._crl:
            self._crl.append(serie)

    def publier_crl(self) -> dict:
        """Publie et signe la CRL."""
        crl = {
            "emetteur":   f"CN={self.nom}",
            "timestamp":  int(time.time()),
            "revoquees":  list(self._crl),
        }
        corps = json.dumps({k: v for k, v in crl.items() if k != "signature"},
                           sort_keys=True).encode()
        crl["signature"] = signer_rsa(corps, self.cle_priv).hex()
        return crl


# ---------------------------------------------------------------------------
# Vérification d'une chaîne de certification
# ---------------------------------------------------------------------------

def verifier_certificat(
    cert: dict,
    cert_emetteur: dict,
    crl: dict | None = None,
    maintenant: int | None = None,
) -> tuple[bool, str]:
    """
    Vérifie un certificat :
    1. Signature de l'émetteur
    2. Dates de validité
    3. Usage (CA autorisé à émettre)
    4. Non révoqué (si CRL fournie)
    Retourne (valide, raison).
    """
    if maintenant is None:
        maintenant = int(time.time())

    # 1. Signature
    cle_pub_emetteur = {k: int(v, 16) for k, v in cert_emetteur["cle_publique"].items()}
    sig = bytes.fromhex(cert["signature"])
    if not verifier_signature_rsa(_corps_cert(cert), sig, cle_pub_emetteur):
        return False, "Signature invalide"

    # 2. Validité temporelle
    if maintenant < cert["not_before"]:
        return False, "Certificat pas encore valide"
    if maintenant > cert["not_after"]:
        return False, "Certificat expiré"

    # 3. L'émetteur doit être une CA
    if "ca" not in cert_emetteur.get("usage", []):
        return False, "L'emetteur n'est pas une AC"

    # 4. Révocation
    if crl is not None:
        if cert["serie"] in crl.get("revoquees", []):
            return False, "Certificat révoqué"

    return True, "OK"


def verifier_chaine(
    cert_feuille: dict,
    chaine: list[dict],   # [cert_intermediaire, ..., cert_racine]
    cert_racine_confiance: dict,
    crl: dict | None = None,
    maintenant: int | None = None,
) -> tuple[bool, str]:
    """
    Vérifie une chaîne complète : feuille → intermédiaires → racine.
    cert_racine_confiance : le certificat racine préinstallé (de confiance).
    """
    # Vérifier la racine (auto-signée)
    cle_pub_racine = {k: int(v, 16) for k, v in cert_racine_confiance["cle_publique"].items()}
    sig_racine = bytes.fromhex(cert_racine_confiance["signature"])
    if not verifier_signature_rsa(_corps_cert(cert_racine_confiance), sig_racine, cle_pub_racine):
        return False, "Racine : signature auto-signée invalide"

    # Vérifier du haut vers le bas
    tous = chaine + [cert_feuille]
    emetteur_courant = cert_racine_confiance
    for cert in tous:
        ok, raison = verifier_certificat(cert, emetteur_courant, crl, maintenant)
        if not ok:
            return False, f"Echec sur '{cert['sujet']}' : {raison}"
        emetteur_courant = cert

    return True, "Chaine valide"


# ---------------------------------------------------------------------------
# Keystore : stockage chiffré de la clé privée
# ---------------------------------------------------------------------------

def _deriver_cle_keystore(mot_de_passe: str, sel: bytes) -> bytes:
    """Dérive une clé AES-256 à partir du mot de passe (PBKDF2)."""
    return hashlib.pbkdf2_hmac("sha256", mot_de_passe.encode(), sel, 200_000)


def keystore_creer(cle_privee: dict, mot_de_passe: str) -> dict:
    """
    Chiffre la clé privée avec AES-GCM dérivé du mot de passe.
    Retourne un dict sérialisable (le keystore).
    """
    sel   = os.urandom(16)
    nonce = os.urandom(12)
    cle_aes = _deriver_cle_keystore(mot_de_passe, sel)
    # Sérialiser la clé privée
    priv_json = json.dumps({k: hex(v) for k, v in cle_privee.items()}).encode()
    chiffre, tag = aes_gcm_chiffrer(cle_aes, nonce, priv_json)
    return {
        "sel":     sel.hex(),
        "nonce":   nonce.hex(),
        "tag":     tag.hex(),
        "chiffre": chiffre.hex(),
    }


def keystore_charger(keystore: dict, mot_de_passe: str) -> dict:
    """
    Déchiffre et retourne la clé privée.
    Lève ValueError si le mot de passe est incorrect.
    """
    sel     = bytes.fromhex(keystore["sel"])
    nonce   = bytes.fromhex(keystore["nonce"])
    tag     = bytes.fromhex(keystore["tag"])
    chiffre = bytes.fromhex(keystore["chiffre"])
    cle_aes = _deriver_cle_keystore(mot_de_passe, sel)
    try:
        priv_json = aes_gcm_dechiffrer(cle_aes, nonce, chiffre, tag)
    except ValueError:
        raise ValueError("Mot de passe incorrect ou keystore corrompu.")
    priv_hex = json.loads(priv_json)
    return {k: int(v, 16) for k, v in priv_hex.items()}


def keystore_changer_mdp(
    keystore: dict,
    ancien_mdp: str,
    nouveau_mdp: str,
) -> dict:
    """Reprotège le keystore avec un nouveau mot de passe."""
    cle_privee = keystore_charger(keystore, ancien_mdp)
    return keystore_creer(cle_privee, nouveau_mdp)


# ---------------------------------------------------------------------------
# Scénario de démonstration complet
# ---------------------------------------------------------------------------

def demo_pki() -> dict:
    """
    Crée une hiérarchie AC racine → AC intermédiaire → certificat utilisateur.
    Émet, vérifie, révoque, et montre les rejets.
    """
    # 1. Racine
    ac_racine = AutoriteCertification("RacineCA", cle_bits=512)
    cert_racine = ac_racine.creer_cert_racine()

    # 2. Intermédiaire
    ac_inter = AutoriteCertification("InterCA", cle_bits=512)
    cert_inter = ac_racine.emettre_certificat(
        f"CN=InterCA", ac_inter.cle_pub, usage=[], est_ca=True
    )
    ac_inter.cert_propre = cert_inter

    # 3. Utilisateur Alice
    cles_alice = generer_cles_rsa(bits=512)
    cert_alice = ac_inter.emettre_certificat(
        "CN=Alice", cles_alice["publique"], usage=["signature", "chiffrement"]
    )

    # 4. Vérification de la chaîne
    ok, raison = verifier_chaine(
        cert_alice, [cert_inter], cert_racine
    )

    # 5. Révocation
    ac_inter.revoquer(cert_alice["serie"])
    crl = ac_inter.publier_crl()
    ok_apres, raison_apres = verifier_chaine(
        cert_alice, [cert_inter], cert_racine, crl=crl
    )

    # 6. Keystore Alice
    mdp = "motdepasse_alice"
    ks  = keystore_creer(cles_alice["privee"], mdp)
    priv_recuperee = keystore_charger(ks, mdp)
    keystore_ok = priv_recuperee["d"] == cles_alice["privee"]["d"]

    return {
        "chaine_valide_avant_revocation": ok,
        "raison_avant":                   raison,
        "chaine_valide_apres_revocation": ok_apres,
        "raison_apres":                   raison_apres,
        "keystore_ok":                    keystore_ok,
    }
