# CryptoVault

Plateforme de messagerie chiffrée de bout en bout et de coffre-fort de fichiers sécurisé.  
Projet intégrateur — Cours Cryptographie (20 h) — Python 3.10+

---

## Installation

```bash
# Cloner le dépôt
git clone <url-du-depot>
cd CryptoVault

# Installer les dépendances
pip install pycryptodome pytest
```

Dépendances :
- `pycryptodome` — AES (modes ECB, CBC, CTR, GCM)
- `pytest` — exécution des tests

Tout le reste (RSA, DH, courbes elliptiques, HMAC, PBKDF2, Merkle, PRNG) est implémenté sans bibliothèque cryptographique externe, en Python pur.

---

## Lancer les tests

```bash
# Tous les tests (254 tests)
python -m pytest tests/

# Un module spécifique
python -m pytest tests/test_hashing.py
python -m pytest tests/test_numtheory.py
python -m pytest tests/test_rsa.py
python -m pytest tests/test_dh.py
python -m pytest tests/test_ecc.py
python -m pytest tests/test_symmetric.py
python -m pytest tests/test_pki.py
python -m pytest tests/test_prng.py
python -m pytest tests/test_integration.py

# Avec détail
python -m pytest tests/ -v
```

---

## Démonstrations

Chaque module cryptolib peut être exécuté directement :

```bash
# Module 1 : hachage, HMAC, mots de passe, Merkle, collision
python -m cryptolib.hashing

# Module 2 : arithmétique modulaire, Miller-Rabin, génération de premiers
python -m cryptolib.numtheory

# Module 3 : RSA, OAEP, signature, chiffrement hybride
python -m cryptolib.rsa

# Module 4 : Diffie-Hellman, HKDF, PFS
python -m cryptolib.dh

# Module 5 : courbes elliptiques, ECDH, ECDSA
python -m cryptolib.ecc

# Module 6 : César, Vigenère, AES, modes, cryptanalyse
python -m cryptolib.symmetric

# Module 8 : LCG, MT19937, HMAC_DRBG, tests statistiques
python -m cryptolib.prng
```

### Attaques pédagogiques

```bash
# Module 3 : Pollard-rho, malléabilité RSA, racine cubique, facteur commun
python -m lab.attaques_rsa

# Module 4 : homme du milieu DH, BSGS
python -m lab.attaques_dh

# Module 5 : nonce ECDSA réutilisé → clé privée retrouvée
python -m lab.attaques_ecc

# Module 6 : ECB motif visible, bit-flipping CBC, OTP réutilisation
python -m lab.attaques_sym

# Module 8 : casser un LCG, cloner le Mersenne Twister
python -m lab.attaques_prng
```

---

## Structure du projet

```
cryptovault/
├── cryptolib/           # bibliothèque cryptographique (modules 1-8)
│   ├── hashing.py       # SHA-*, HMAC-SHA256, PBKDF2, arbre de Merkle
│   ├── numtheory.py     # pgcd, egcd, CRT, Miller-Rabin, generate_prime
│   ├── rsa.py           # RSA, OAEP, PSS, CRT accéléré, chiffrement hybride
│   ├── dh.py            # Diffie-Hellman MODP-2048, HKDF (RFC 5869)
│   ├── ecc.py           # P-256, secp256k1, ECDH, ECDSA, RFC 6979
│   ├── symmetric.py     # César, Vigenère, OTP, AES ECB/CBC/CTR/GCM
│   ├── pki.py           # AC hiérarchique, certificats JSON, CRL, keystore
│   └── prng.py          # LCG, MT19937, HMAC_DRBG, tests statistiques
├── app/                 # application intégrée (module 9)
│   ├── server.py        # serveur TLS simplifié
│   ├── client.py        # client messagerie
│   └── vault.py         # coffre-fort de fichiers
├── lab/                 # attaques pédagogiques
│   ├── attaques_rsa.py
│   ├── attaques_dh.py
│   ├── attaques_ecc.py
│   ├── attaques_sym.py
│   └── attaques_prng.py
├── tests/               # tests unitaires et d'intégration
└── report/              # rapport PDF
```

---

## Tableau de traçabilité

| Fonctionnalité | Modules utilisés | Chapitres cours |
|---|---|---|
| Stockage mot de passe | hashing (PBKDF2, sel) | 1 |
| Intégrité de fichier | hashing (Merkle) | 1 |
| Génération de clés RSA | numtheory (Miller-Rabin, generate_prime) | 2, 3 |
| Chiffrement RSA-OAEP | rsa, numtheory | 2, 3 |
| Signature RSA | rsa | 3 |
| Échange de clés DH | dh, numtheory | 2, 4 |
| Dérivation de clés HKDF | dh (hkdf), hashing (HMAC) | 1, 4 |
| Chiffrement symétrique | symmetric (AES-GCM) | 6 |
| ECDH (échange de clés) | ecc, numtheory | 2, 5 |
| ECDSA (signature) | ecc | 5 |
| Certificats et PKI | pki, rsa | 3, 7 |
| Keystore chiffré | pki, symmetric, hashing | 1, 6, 7 |
| Aléa cryptographique | prng (HMAC_DRBG) | 8 |
| **Handshake messagerie** | ecc, dh, symmetric, pki, prng | 4, 5, 6, 7, 8 |
| **Coffre-fort** | rsa, ecc, symmetric, hashing, prng | 1, 3, 5, 6, 8 |

---

## Remarque de sécurité

Ce projet est un exercice pédagogique. Les implémentations manuelles de RSA, DH et ECC ne sont **pas** résistantes aux attaques par canaux auxiliaires et ne doivent pas être utilisées en production. Pour des systèmes réels, utilisez des bibliothèques éprouvées (OpenSSL, libsodium, cryptography.io).
