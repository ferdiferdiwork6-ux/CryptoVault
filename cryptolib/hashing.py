"""
Module 1 : Hachage, HMAC, mots de passe, arbre de Merkle.
"""
from __future__ import annotations
import hashlib
import hmac as _hmac_stdlib
import os
import time


# ---------------------------------------------------------------------------
# Empreintes de fichier
# ---------------------------------------------------------------------------

def calculer_empreintes(chemin: str) -> dict:
    """Calcule MD5, SHA-1, SHA-256 et SHA3-256 d'un fichier."""
    algorithmes = {
        "MD5":     hashlib.md5(),
        "SHA-1":   hashlib.sha1(),
        "SHA-256": hashlib.sha256(),
        "SHA3-256":hashlib.sha3_256(),
    }
    with open(chemin, "rb") as f:
        for bloc in iter(lambda: f.read(4096), b""):
            for h in algorithmes.values():
                h.update(bloc)
    return {nom: h.hexdigest() for nom, h in algorithmes.items()}


def verifier_empreinte(chemin: str, empreinte_attendue: str, algorithme: str = "sha256") -> bool:
    """Vérifie si un fichier correspond à une empreinte attendue."""
    empreintes = calculer_empreintes(chemin)
    noms = {
        "md5": "MD5", "sha1": "SHA-1", "sha-1": "SHA-1",
        "sha256": "SHA-256", "sha-256": "SHA-256",
        "sha3-256": "SHA3-256", "sha3_256": "SHA3-256",
    }
    nom = noms.get(algorithme.lower())
    if nom is None:
        raise ValueError("Algorithme non pris en charge.")
    return empreintes[nom].lower() == empreinte_attendue.lower()


# ---------------------------------------------------------------------------
# Effet avalanche
# ---------------------------------------------------------------------------

def effet_avalanche(message: bytes, algorithme: str = "sha256") -> dict:
    """Flippe un bit du message et mesure le nombre de bits changés en sortie."""
    h = hashlib.new(algorithme)
    h.update(message)
    digest_orig = h.digest()
    n_bits = len(digest_orig) * 8

    resultats = []
    for octet_idx in range(min(len(message), 4)):
        for bit_idx in range(8):
            m2 = bytearray(message)
            m2[octet_idx] ^= (1 << bit_idx)
            h2 = hashlib.new(algorithme)
            h2.update(bytes(m2))
            bits = sum(bin(a ^ b).count("1") for a, b in zip(digest_orig, h2.digest()))
            resultats.append(bits)

    moyenne = sum(resultats) / len(resultats)
    return {
        "algorithme": algorithme,
        "bits_sortie": n_bits,
        "moyenne_bits_changes": moyenne,
        "pourcentage": moyenne / n_bits * 100,
        "details": resultats,
    }


# ---------------------------------------------------------------------------
# HMAC-SHA256 (RFC 2104, implémentation manuelle)
# ---------------------------------------------------------------------------

_BLOC_SHA256 = 64

def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def hmac_sha256(cle: bytes, message: bytes) -> bytes:
    """HMAC-SHA256 selon RFC 2104. Implémenté sans le module hmac."""
    if len(cle) > _BLOC_SHA256:
        cle = _sha256(cle)
    if len(cle) < _BLOC_SHA256:
        cle = cle + b"\x00" * (_BLOC_SHA256 - len(cle))
    ipad = bytes(b ^ 0x36 for b in cle)
    opad = bytes(b ^ 0x5C for b in cle)
    return _sha256(opad + _sha256(ipad + message))

def comparer_temps_constant(a: bytes, b: bytes) -> bool:
    """Comparaison en temps constant pour éviter les attaques temporelles."""
    if len(a) != len(b):
        return False
    r = 0
    for x, y in zip(a, b):
        r |= x ^ y
    return r == 0


# ---------------------------------------------------------------------------
# Stockage de mots de passe (sel + PBKDF2-HMAC-SHA256)
# ---------------------------------------------------------------------------

def hacher_mot_de_passe(mot_de_passe: str, iterations: int = 260_000) -> tuple[str, float]:
    """
    Retourne (chaine_stockee, duree_secondes).
    Format : pbkdf2_sha256$iterations$sel_hex$hash_hex
    """
    sel = os.urandom(16)
    debut = time.time()
    h = hashlib.pbkdf2_hmac("sha256", mot_de_passe.encode(), sel, iterations)
    duree = time.time() - debut
    return f"pbkdf2_sha256${iterations}${sel.hex()}${h.hex()}", duree

def verifier_mot_de_passe(mot_de_passe: str, stocke: str) -> bool:
    """Vérifie un mot de passe contre le haché stocké."""
    parties = stocke.split("$")
    if len(parties) != 4 or parties[0] != "pbkdf2_sha256":
        raise ValueError("Format de stockage invalide.")
    _, iterations, sel_hex, hash_hex = parties
    sel = bytes.fromhex(sel_hex)
    h = hashlib.pbkdf2_hmac("sha256", mot_de_passe.encode(), sel, int(iterations))
    return comparer_temps_constant(h, bytes.fromhex(hash_hex))


# ---------------------------------------------------------------------------
# Arbre de Merkle
# ---------------------------------------------------------------------------

def _hacher_feuille(bloc: bytes) -> bytes:
    return _sha256(b"\x00" + bloc)

def _hacher_noeud(g: bytes, d: bytes) -> bytes:
    return _sha256(b"\x01" + g + d)

def construire_merkle(blocs: list) -> list:
    """Retourne les niveaux de l'arbre (feuilles en [0], racine en [-1])."""
    if not blocs:
        raise ValueError("Liste de blocs vide.")
    niveau = [_hacher_feuille(b) for b in blocs]
    if len(niveau) % 2 == 1:
        niveau.append(niveau[-1])
    niveaux = [niveau]
    while len(niveau) > 1:
        suivant = []
        for i in range(0, len(niveau), 2):
            d = niveau[i+1] if i+1 < len(niveau) else niveau[i]
            suivant.append(_hacher_noeud(niveau[i], d))
        if len(suivant) > 1 and len(suivant) % 2 == 1:
            suivant.append(suivant[-1])
        niveaux.append(suivant)
        niveau = suivant
    return niveaux

def racine_merkle(blocs: list) -> bytes:
    return construire_merkle(blocs)[-1][0]

def preuve_merkle(blocs: list, index: int) -> list:
    """Retourne la liste de (direction, hash) pour la preuve d'appartenance."""
    niveaux = construire_merkle(blocs)
    preuve = []
    idx = index
    for niveau in niveaux[:-1]:
        if idx % 2 == 0:
            frere = idx+1 if idx+1 < len(niveau) else idx
            preuve.append(("droite", niveau[frere]))
        else:
            preuve.append(("gauche", niveau[idx-1]))
        idx //= 2
    return preuve

def verifier_preuve_merkle(bloc: bytes, index: int, preuve: list, racine: bytes) -> bool:
    """Vérifie une preuve d'appartenance de Merkle."""
    h = _hacher_feuille(bloc)
    for direction, frere in preuve:
        if direction == "droite":
            h = _hacher_noeud(h, frere)
        else:
            h = _hacher_noeud(frere, h)
    return comparer_temps_constant(h, racine)

def merkle_sur_fichier(chemin: str, taille_bloc: int = 1024) -> dict:
    blocs = []
    with open(chemin, "rb") as f:
        while True:
            b = f.read(taille_bloc)
            if not b:
                break
            blocs.append(b)
    if not blocs:
        raise ValueError("Fichier vide.")
    return {"racine": racine_merkle(blocs).hex(), "nb_blocs": len(blocs), "blocs": blocs}


# ---------------------------------------------------------------------------
# Attaque anniversaire sur SHA-256 tronqué à 32 bits
# ---------------------------------------------------------------------------

def attaque_anniversaire_32bits(max_essais: int = 2**17) -> dict:
    """Cherche une collision sur SHA-256 tronqué aux 32 premiers bits."""
    vus = {}
    debut = time.time()
    for i in range(max_essais):
        msg = i.to_bytes(8, "big")
        digest = _sha256(msg)[:4]
        if digest in vus:
            return {
                "collision_trouvee": True,
                "essais": i + 1,
                "theorique_2_16": 2**16,
                "message1": vus[digest].hex(),
                "message2": msg.hex(),
                "empreinte_tronquee": digest.hex(),
                "duree_secondes": round(time.time() - debut, 4),
            }
        vus[digest] = msg
    return {"collision_trouvee": False, "essais": max_essais}


# ---------------------------------------------------------------------------
# Démonstration
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    chemin = "test.txt"
    try:
        empreintes = calculer_empreintes(chemin)
        print("Fichier :", chemin)
        for algo, val in empreintes.items():
            print(f"  {algo}: {val}")
        print()

        with open(chemin, "rb") as f:
            contenu = f.read(64)
        av = effet_avalanche(contenu)
        print(f"Effet avalanche : {av['pourcentage']:.1f}% bits changes (attendu ~50%)")
        print()

        cle = b"cle_secrete"
        msg = b"message de test"
        tag = hmac_sha256(cle, msg)
        tag_ref = _hmac_stdlib.new(cle, msg, hashlib.sha256).digest()
        print(f"HMAC-SHA256 : {tag.hex()}")
        print(f"Match stdlib : {comparer_temps_constant(tag, tag_ref)}")
        print()

        stocke, duree = hacher_mot_de_passe("motdepasse", iterations=100_000)
        print(f"Mot de passe : {stocke[:60]}...")
        print(f"Duree        : {duree*1000:.1f} ms")
        print(f"Verif OK     : {verifier_mot_de_passe('motdepasse', stocke)}")
        print()

        print("Attaque anniversaire 32 bits...")
        res = attaque_anniversaire_32bits()
        if res["collision_trouvee"]:
            print(f"  Collision en {res['essais']} essais (theorique ~{res['theorique_2_16']})")

    except FileNotFoundError:
        print("Erreur : fichier test.txt introuvable.")
