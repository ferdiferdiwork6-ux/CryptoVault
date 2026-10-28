"""
Bonus : Comparaison ECDH P-256 vs ML-KEM (post-quantique, NIST 2024).
ML-KEM = Module Lattice Key Encapsulation Mechanism (ex-Kyber).
Standardisé dans FIPS 203 (2024).

Nécessite : pip install kyber-py
"""
from __future__ import annotations
import os
import time
from kyber_py.ml_kem import ML_KEM_512, ML_KEM_768, ML_KEM_1024


# Niveaux de sécurité disponibles
NIVEAUX = {
    "ML-KEM-512":  ML_KEM_512,   # ~128 bits (comme AES-128)
    "ML-KEM-768":  ML_KEM_768,   # ~192 bits
    "ML-KEM-1024": ML_KEM_1024,  # ~256 bits (recommandé pour PQC)
}


# ---------------------------------------------------------------------------
# Interface d'échange de clés ML-KEM (KEM = Key Encapsulation Mechanism)
# ---------------------------------------------------------------------------

def mlkem_generer_cle(niveau: str = "ML-KEM-768") -> tuple[bytes, bytes]:
    """
    Génère une paire de clés ML-KEM.
    Retourne (ek, dk) = (encapsulation key / publique, decapsulation key / privée).
    """
    kem = NIVEAUX[niveau]
    ek, dk = kem.keygen()
    return ek, dk


def mlkem_encapsuler(ek: bytes, niveau: str = "ML-KEM-768") -> tuple[bytes, bytes]:
    """
    Encapsule un secret partagé avec la clé publique.
    Retourne (secret_partage, ciphertext).
    Le secret partagé fait 32 octets (256 bits).
    """
    kem = NIVEAUX[niveau]
    secret, ciphertext = kem.encaps(ek)
    return secret, ciphertext


def mlkem_decapsuler(dk: bytes, ciphertext: bytes, niveau: str = "ML-KEM-768") -> bytes:
    """
    Décapsule et retrouve le secret partagé avec la clé privée.
    Retourne le secret partagé de 32 octets.
    """
    kem = NIVEAUX[niveau]
    return kem.decaps(dk, ciphertext)


# ---------------------------------------------------------------------------
# Comparaison ECDH P-256 vs ML-KEM (performance + tailles)
# ---------------------------------------------------------------------------

def comparer_ecdh_mlkem(n_essais: int = 5) -> dict:
    """
    Mesure et compare les performances de ECDH P-256 et ML-KEM-768.
    Retourne un dict avec les temps et les tailles.
    """
    from cryptolib.ecc import P256, ecdh_generer_cle, ecdh_secret_partage

    resultats = {}

    # ── ECDH P-256 ─────────────────────────────────────────────────────────
    debut = time.perf_counter()
    for _ in range(n_essais):
        d_a, Q_a = ecdh_generer_cle(P256)
        d_b, Q_b = ecdh_generer_cle(P256)
        K_a = ecdh_secret_partage(d_a, Q_b, P256)
        K_b = ecdh_secret_partage(d_b, Q_a, P256)
        assert K_a == K_b
    t_ecdh = (time.perf_counter() - debut) / n_essais * 1000  # ms par échange

    nb = (P256.p.bit_length() + 7) // 8
    taille_cle_pub_ecdh  = 2 * nb        # point non compressé (x, y)
    taille_cle_priv_ecdh = nb            # scalaire
    taille_msg_ecdh      = 2 * nb        # valeur publique éphémère

    resultats["ECDH P-256"] = {
        "securite_bits":       128,
        "resistance_quantique": False,
        "taille_cle_pub_octets":  taille_cle_pub_ecdh,
        "taille_cle_priv_octets": taille_cle_priv_ecdh,
        "taille_ciphertext_octets": taille_msg_ecdh,
        "taille_secret_octets": nb,
        "temps_echange_ms":    round(t_ecdh, 3),
    }

    # ── ML-KEM-768 ──────────────────────────────────────────────────────────
    debut = time.perf_counter()
    for _ in range(n_essais):
        ek, dk = mlkem_generer_cle("ML-KEM-768")
        secret_a, ct = mlkem_encapsuler(ek, "ML-KEM-768")
        secret_b     = mlkem_decapsuler(dk, ct, "ML-KEM-768")
        assert secret_a == secret_b
    t_mlkem = (time.perf_counter() - debut) / n_essais * 1000

    resultats["ML-KEM-768"] = {
        "securite_bits":       192,
        "resistance_quantique": True,
        "taille_cle_pub_octets":  len(ek),
        "taille_cle_priv_octets": len(dk),
        "taille_ciphertext_octets": len(ct),
        "taille_secret_octets": len(secret_a),
        "temps_echange_ms":    round(t_mlkem, 3),
    }

    return resultats


def echange_hybride_x25519_mlkem() -> dict:
    """
    Simule un échange hybride X25519 + ML-KEM-768 :
    le secret final est HKDF(secret_ecdh || secret_mlkem).
    Si l'un des deux est cassé, l'autre protège toujours.
    """
    from cryptolib.ecc import P256, ecdh_generer_cle, ecdh_secret_partage
    from cryptolib.dh import hkdf

    # ── Partie ECDH ──
    d_a, Q_a = ecdh_generer_cle(P256)
    d_b, Q_b = ecdh_generer_cle(P256)
    secret_ecdh_a = ecdh_secret_partage(d_a, Q_b, P256)
    secret_ecdh_b = ecdh_secret_partage(d_b, Q_a, P256)
    assert secret_ecdh_a == secret_ecdh_b

    # ── Partie ML-KEM ──
    ek, dk = mlkem_generer_cle("ML-KEM-768")
    secret_mlkem_a, ct = mlkem_encapsuler(ek, "ML-KEM-768")
    secret_mlkem_b     = mlkem_decapsuler(dk, ct, "ML-KEM-768")
    assert secret_mlkem_a == secret_mlkem_b

    # ── Combinaison HKDF ──
    ikm = secret_ecdh_a + secret_mlkem_a
    cle_hybride_a = hkdf(ikm, 32, info=b"hybrid-x25519-mlkem768")

    ikm2 = secret_ecdh_b + secret_mlkem_b
    cle_hybride_b = hkdf(ikm2, 32, info=b"hybrid-x25519-mlkem768")

    return {
        "secrets_ecdh_egaux":    secret_ecdh_a == secret_ecdh_b,
        "secrets_mlkem_egaux":   secret_mlkem_a == secret_mlkem_b,
        "cles_hybrides_egales":  cle_hybride_a == cle_hybride_b,
        "taille_cle_finale":     len(cle_hybride_a),
        "propriete_hybride": (
            "Si ECDH est casse par Shor, ML-KEM protege. "
            "Si ML-KEM a une faille inconnue, ECDH protege. "
            "Les deux doivent etre cassis simultanement."
        ),
    }


# ---------------------------------------------------------------------------
# Démonstration
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=== Comparaison ECDH P-256 vs ML-KEM ===\n")
    res = comparer_ecdh_mlkem(n_essais=5)
    for nom, stats in res.items():
        print(f"  {nom}")
        print(f"    Securite          : {stats['securite_bits']} bits")
        print(f"    Resistance quantique : {stats['resistance_quantique']}")
        print(f"    Cle publique      : {stats['taille_cle_pub_octets']} octets")
        print(f"    Cle privee        : {stats['taille_cle_priv_octets']} octets")
        print(f"    Ciphertext        : {stats['taille_ciphertext_octets']} octets")
        print(f"    Secret partage    : {stats['taille_secret_octets']} octets")
        print(f"    Temps echange     : {stats['temps_echange_ms']} ms")
        print()

    print("=== Echange hybride X25519 + ML-KEM-768 ===\n")
    h = echange_hybride_x25519_mlkem()
    print(f"  Secrets ECDH egaux    : {h['secrets_ecdh_egaux']}")
    print(f"  Secrets ML-KEM egaux  : {h['secrets_mlkem_egaux']}")
    print(f"  Cles hybrides egales  : {h['cles_hybrides_egales']}")
    print(f"  Taille cle finale     : {h['taille_cle_finale']} octets (AES-256)")
    print(f"\n  Propriete : {h['propriete_hybride']}")
