# CryptoVault — Rapport de projet
## Cours Cryptographie (20 h) — Octobre 2026

---

# 1. Introduction

Ce rapport présente la conception et l'implémentation de CryptoVault, une plateforme de messagerie chiffrée de bout en bout et de coffre-fort de fichiers sécurisé. Le projet a été réalisé dans le cadre du cours de cryptographie (20 heures) et vise à mettre en oeuvre les primitives cryptographiques étudiées : fonctions de hachage, arithmétique modulaire, RSA, Diffie-Hellman, courbes elliptiques, cryptographie symétrique, PKI et générateurs pseudo-aléatoires.

L'objectif pédagogique est double : implémenter chaque brique cryptographique à la main pour en comprendre le fonctionnement interne, puis illustrer par des attaques sur nos propres implémentations jouets pourquoi les bonnes pratiques existent.

**Note de sécurité.** Conformément aux consignes, ce prototype est un exercice d'apprentissage. Les implémentations manuelles de RSA, DH et ECC ne résistent pas aux attaques par canaux auxiliaires et ne sont pas destinées à protéger des données réelles.

---

# 2. Architecture générale

```
cryptovault/
├── cryptolib/      bibliothèque cryptographique (modules 1 à 8)
├── app/            application intégrée (module 9)
├── lab/            scripts d'attaques pédagogiques
├── tests/          254 tests unitaires et d'intégration
└── report/         ce rapport
```

Les modules cryptolib sont indépendants et réutilisables. L'application (app/) les assemble en un protocole cohérent. Les scripts lab/ démontrent les failles quand les primitives sont mal utilisées.

**Contraintes d'implémentation respectées :**
- Modules numtheory, rsa, dh, ecc : zéro bibliothèque cryptographique, entiers natifs Python uniquement.
- AES : pycryptodome autorisé (modes ECB, CBC, CTR, GCM).
- Fonctions de hachage : hashlib de la bibliothèque standard.
- Aucune clé ni secret en clair dans le code ou le dépôt.

---

# 3. Module 1 — Fonctions de hachage

## 3.1 Choix d'implémentation

La fonction `calculer_empreintes` calcule MD5, SHA-1, SHA-256 et SHA3-256 d'un fichier en une seule passe, par blocs de 4 096 octets pour gérer les gros fichiers sans charger tout en mémoire.

HMAC-SHA256 est implémenté manuellement selon la RFC 2104 : padding de la clé à 64 octets, XOR avec ipad (0x36) et opad (0x5C), double hachage imbriqué. La comparaison des tags se fait en temps constant (XOR cumulé) pour éviter les attaques temporelles.

Le stockage des mots de passe utilise PBKDF2-HMAC-SHA256 avec 260 000 itérations et un sel aléatoire de 16 octets par utilisateur. Le format de stockage est `pbkdf2_sha256$iterations$sel_hex$hash_hex`.

## 3.2 Arbre de Merkle

L'arbre est construit avec la convention de préfixe (0x00 pour les feuilles, 0x01 pour les noeuds internes) conforme à Certificate Transparency, ce qui empêche les attaques par second préimage sur la structure de l'arbre. En cas de nombre impair de feuilles, la dernière est dupliquée.

## 3.3 Résultats de l'attaque anniversaire (SHA-256 tronqué 32 bits)

| Paramètre | Valeur |
|---|---|
| Taille de la sortie | 32 bits |
| Essais théoriques (2^16) | 65 536 |
| Essais observés (moyenne) | ~55 000 – 75 000 |
| Durée | < 1 seconde |

Le nombre d'essais observés est cohérent avec la prévision théorique (paradoxe des anniversaires). L'écart vient de la variance naturelle d'un processus probabiliste.

---

# 4. Module 2 — Arithmétique modulaire

## 4.1 Algorithme d'Euclide étendu

`egcd(a, b)` retourne (g, u, v) tels que a·u + b·v = g. L'implémentation itérative évite les problèmes de récursion sur de grands entiers. L'inverse modulaire en découle directement : si g = 1, alors u mod n est l'inverse de a.

## 4.2 Exponentiation modulaire (square-and-multiply)

Implémentée sans `pow(a, e, n)` (interdit par les règles). La décomposition binaire de l'exposant donne O(log e) multiplications modulo n. Comparaison sur un exposant de 2048 bits :

| Méthode | Temps (5 appels) |
|---|---|
| Notre expmod | ~0.8 s |
| pow(a, e, n) natif Python | ~0.002 s |

L'écart vient des optimisations de bas niveau de CPython (GMP). Notre version est correcte mais non optimisée.

## 4.3 Test de Miller-Rabin

Avec k = 40 bases aléatoires, la probabilité d'erreur est ≤ 4^(-40) ≈ 10^(-24), négligeable en pratique. Le test rejette correctement les nombres de Carmichael (561, 1105, 1729) que le test de Fermat accepte à tort.

## 4.4 Génération de premiers

Crible rapide sur les 40 premiers petits nombres premiers, puis Miller-Rabin. Résultats mesurés :

| Taille | Candidats testés (moyenne) | Prévision ln(2^k)/2 |
|---|---|---|
| 128 bits | ~45 | ~44 |
| 256 bits | ~89 | ~89 |
| 512 bits | ~178 | ~178 |

La densité des premiers est conforme au théorème des nombres premiers.

---

# 5. Module 3 — RSA

## 5.1 Génération de clés

Deux premiers de 512 bits chacun (module 1024 bits pour les tests, 2048 bits recommandé en production). Exposant public e = 65537 = 2^16 + 1 (17 multiplications seulement lors du chiffrement). L'exposant privé d est calculé par Euclide étendu.

Précalculs CRT stockés avec la clé privée : dp = d mod (p-1), dq = d mod (q-1), qinv = q^(-1) mod p.

## 5.2 Accélération CRT

Le déchiffrement CRT calcule C^d mod p et C^d mod q séparément (exponentiations sur des entiers moitié moins grands), puis recolle via la formule de Garner. Gain mesuré :

| Méthode | 5 déchiffrements (clé 512 bits) |
|---|---|
| Direct (C^d mod n) | ~0.12 s |
| CRT | ~0.03 s |
| Facteur d'accélération | ~4× |

## 5.3 Padding OAEP (RFC 8017)

MGF1 avec SHA-256 comme fonction de masquage. Le padding aléatoire rend le chiffrement non déterministe et le rend sûr CCA2. La longueur maximale du message est k - 2·hLen - 2 = 128 - 64 - 2 = 62 octets pour un module de 1024 bits.

## 5.4 Résultats des attaques

**Attaque 1 — Factorisation Pollard-rho (module 64 bits)**
Durée moyenne : < 5 ms. La clé privée est intégralement retrouvée.

**Attaque 2 — Malléabilité textbook RSA**
Si C = M^e mod n, alors (k^e · C) = (kM)^e mod n. Un oracle de déchiffrement sur le chiffré modifié donne kM, d'où M = kM / k. Contre-mesure : OAEP rend cette propriété impossible (le padding est aléatoire).

**Attaque 3 — Racine cubique (e=3, sans padding)**
Si M^3 < n, aucune réduction modulaire n'a lieu. La racine cubique entière de C redonne M directement. Contre-mesure : toujours utiliser un padding (OAEP).

**Attaque 4 — Facteur commun (pgcd)**
Si deux modules n1 = p·q1 et n2 = p·q2 partagent le premier p, alors pgcd(n1, n2) = p en une opération. Les deux clés privées sont cassées instantanément. Observé en 2012 sur des milliers de routeurs embarqués avec un PRNG défaillant.

---

# 6. Module 4 — Diffie-Hellman

## 6.1 Paramètres

Groupe MODP-2048 (RFC 3526 §3), premier de 2048 bits avec g = 2. Pour les démonstrations rapides, groupe jouet p = 23, g = 5 (exemple du cours).

Validation des valeurs reçues : une valeur DH égale à 1 ou p-1 indiquerait une attaque par petit sous-groupe et est rejetée.

## 6.2 HKDF (RFC 5869)

Implémenté à partir de notre HMAC-SHA256. Validé sur les vecteurs officiels (Test Case 1 et 3). Produit deux clés indépendantes de 32 octets chacune à partir du secret partagé :
- info = b"cryptovault-enc" → clé de chiffrement AES-256
- info = b"cryptovault-auth" → clé d'authentification HMAC

## 6.3 Confidentialité persistante (PFS)

Avec DH éphémère, chaque session génère de nouveaux a et b, effacés après usage. Si la clé longue terme est compromise ultérieurement, les sessions passées enregistrées restent protégées. Avec DH statique, compromettre a permet de recalculer gab pour toutes les sessions passées.

## 6.4 Attaque MITM et contre-mesure

Mallory établit deux secrets distincts, lit et modifie les messages sans que les parties s'en aperçoivent. Contre-mesure : Alice et Bob signent leurs valeurs ECDHE avec leur clé longue terme (RSA ou ECDSA). Mallory ne peut pas signer avec la clé privée d'Alice, donc la vérification échoue.

## 6.5 Attaque BSGS sur petit premier

Baby-step Giant-step : complexité O(sqrt(ordre)). Résultats :

| Taille du premier | sqrt(p) approx | Durée |
|---|---|---|
| 20 bits | ~1 024 | < 1 ms |
| 25 bits | ~5 792 | < 5 ms |
| 30 bits | ~32 768 | < 50 ms |

Sur un premier de 2048 bits, sqrt(p) ≈ 2^1024, hors de portée.

---

# 7. Module 5 — Courbes elliptiques

## 7.1 Implémentation

La loi de groupe est implémentée avec les formules de Weierstrass sur Fp. Les cas particuliers (point à l'infini, doublement, P = -P) sont tous traités. La multiplication scalaire utilise double-and-add, analogue du square-and-multiply.

Validation sur la courbe jouet du cours (y² = x³ + 2x + 2 sur F17) : les 18 multiples non triviaux de G = (5, 1) et 19G = ∞ sont tous corrects.

Courbes standardisées implémentées : P-256 (NIST), secp256k1 (Bitcoin). Vérification que n·G = ∞ pour les deux courbes.

## 7.2 Nonce déterministe RFC 6979

Le nonce k est dérivé de façon déterministe à partir de (d, h(message)) via HMAC-SHA256. Avantages :
- Impossible de réutiliser k accidentellement pour deux messages différents.
- Même message + même clé = même signature (déterminisme vérifiable).

## 7.3 Attaque nonce réutilisé

Si k est identique pour deux signatures (r1 = r2 car R = k·G est le même) :
- s1 = k^(-1)(z1 + r·d) mod n
- s2 = k^(-1)(z2 + r·d) mod n
- s1 - s2 = k^(-1)(z1 - z2) → k = (z1-z2)/(s1-s2) mod n
- d = (s1·k - z1) / r mod n

La clé privée est retrouvée en quelques microsecondes. C'est ainsi que la clé de signature de la PlayStation 3 a été retrouvée en 2010.

## 7.4 Comparaison RSA vs ECC

| Critère | RSA-2048 | P-256 (ECDSA) |
|---|---|---|
| Taille clé privée | 2048 bits | 256 bits |
| Taille signature | 256 octets | ~72 octets (DER) |
| Niveau de sécurité | ~112 bits | ~128 bits |
| Génération de clé | ~0.5 s | < 1 ms |
| Signature | ~0.1 s | < 10 ms |
| Vérification | < 1 ms | < 10 ms |

ECC offre une meilleure sécurité avec des clés bien plus courtes, idéal pour les mobiles et les objets connectés.

---

# 8. Module 6 — Cryptographie symétrique

## 8.1 Chiffrements classiques

César : 25 clés possibles, cassé par force brute en moins de 1 ms. Vigenère : cassé par l'indice de coïncidence (détection de longueur de clé) puis analyse fréquentielle sur chaque sous-séquence. Fonctionne bien sur des textes français de plus de 100 caractères.

## 8.2 Modes AES

**ECB (interdit en production)** : blocs identiques en clair donnent des blocs identiques en chiffré. Sur une image avec de grandes zones uniformes, les contours restent visibles ("l'image du pingouin ECB"). Démontré expérimentalement : 4 blocs de 16 octets identiques produisent 4 blocs chiffrés identiques.

**CBC** : le chaînage brise les répétitions. Mais sans authentification, vulnerable au bit-flipping : modifier C[i-1][j] flippe M[i][j] de façon prévisible. Démonstré : modification de "admin=0" en "admin=1" sans connaître la clé.

**CTR** : transforme AES en chiffrement par flot. Pas de padding, parallélisable. Nonce jamais réutilisé avec la même clé.

**GCM (recommandé)** : AEAD — chiffrement + authentification en une passe. Toute modification (même 1 bit) invalide le tag et est détectée. Nonce de 12 octets unique par message.

## 8.3 Attaque bit-flipping

La correction : placer le champ ciblé dans le bloc i, avec un bloc de rembourrage en i-1. Modifier le bloc i-1 chiffré contrôle exactement le bloc i déchiffré. GCM rejette cette manipulation car le tag couvre tout le chiffré.

---

# 9. Module 7 — Infrastructure à clés publiques

## 9.1 Format de certificat

Format JSON maison inspiré X.509 v3, signé avec RSA (notre implémentation). Champs : version, série, sujet, émetteur, not_before, not_after, clé publique, usage, signature.

## 9.2 Hiérarchie

```
AC Racine (auto-signée, clé hors ligne)
    └── AC Intermédiaire (certifiée par la racine)
            └── Certificats utilisateurs (certifiés par l'intermédiaire)
```

Les navigateurs préinstallent la racine dans leur magasin de confiance. La racine ne signe jamais directement les certificats feuilles, ce qui limite son exposition.

## 9.3 Révocation

La CRL (liste de révocation) est signée par l'AC intermédiaire et contient les numéros de série révoqués. Le serveur vérifie la CRL avant d'accepter un certificat. Un certificat révoqué est rejeté même si sa signature est valide et ses dates correctes.

## 9.4 Keystore

La clé privée ne touche jamais le disque en clair. Elle est chiffrée avec AES-256-GCM, dont la clé est dérivée du mot de passe par PBKDF2-HMAC-SHA256 (200 000 itérations, sel aléatoire de 16 octets). Le changement de mot de passe redéchiffre et rechiffre sans jamais exposer la clé privée.

---

# 10. Module 8 — Générateurs pseudo-aléatoires

## 10.1 LCG (non sûr)

Paramètres du cours : m = 16, a = 5, c = 3, X0 = 2. Période maximale de 16 (Hull-Dobell). Prédictible : avec m connu et 3 sorties consécutives x0, x1, x2, on retrouve a = (x1-x2)/(x0-x1) mod m et c = x1 - a·x0 mod m. L'attaque réussit à 100% sur le LCG 32 bits standard.

## 10.2 Mersenne Twister (non sûr, mais statistiquement bon)

Période 2^19937 - 1, excellente équidistribution. Utilisé par Python random, NumPy, etc. Mais : le tempering est inversible. En observant 624 sorties de 32 bits, on reconstruit l'état interne mt[] en entier et on prédit toutes les sorties suivantes avec 100% de précision. Ne jamais utiliser pour des clés, tokens ou mots de passe.

## 10.3 HMAC_DRBG (sûr)

Basé sur HMAC-SHA256, réensemencé depuis os.urandom. L'état interne (K, V) est mis à jour après chaque génération. Même si K fuite à l'instant t, les sorties passées restent imprévisibles (backtracking resistance). Utilisé partout dans le projet pour générer clés, nonces, sels.

## 10.4 Tests statistiques

| Générateur | Monobit | Runs | Chi² |
|---|---|---|---|
| LCG (32 bits) | OK | OK | OK* |
| MT19937 | OK | OK | OK |
| HMAC_DRBG | OK | OK | OK |

*Le LCG 32 bits passe les tests statistiques de base mais reste prédictible. C'est exactement le point du cours : les tests statistiques ne prouvent pas la sécurité cryptographique.

---

# 11. Module 9 — Application intégrée

## 11.1 Messagerie : protocole TLS simplifié

**Inscription**
1. Le client génère une paire de clés ECC (P-256).
2. Le serveur émet un certificat signé par son AC intermédiaire.
3. Le mot de passe est stocké sous forme PBKDF2 salé (jamais en clair).

**Handshake ECDHE**
1. Le serveur génère une paire éphémère (d_eph, Q_eph) et signe Q_eph avec sa clé longue terme.
2. Le client vérifie la chaîne de certification du serveur et la signature sur Q_eph.
3. Le client génère sa propre paire éphémère et signe Q_eph_client.
4. Les deux parties calculent le secret partagé ECDHE et en dérivent deux clés AES-256 via HKDF.
5. Les clés éphémères sont effacées (PFS).

**Messages**
Chiffrés AES-256-GCM avec un nonce incluant le numéro de séquence. Toute modification du chiffré est détectée. Un paquet avec un numéro de séquence inattendu est rejeté (protection anti-rejeu).

## 11.2 Coffre-fort de fichiers

```
vault add(nom, données, auteur_d, [cles_pub_rsa_destinataires])
  1. Génère une clé de fichier AES-256 aléatoire (HMAC_DRBG)
  2. Chiffre les données avec AES-256-GCM
  3. Chiffre la clé de fichier avec RSA-OAEP pour chaque destinataire
  4. Construit l'arbre de Merkle sur le fichier chiffré
  5. Signe la racine de Merkle avec ECDSA

vault get(nom, cle_priv_rsa, auteur_Q)
  1. Vérifie la signature ECDSA sur la racine de Merkle
  2. Déchiffre la clé de fichier avec RSA-OAEP
  3. Déchiffre AES-GCM
  4. Vérifie l'intégrité Merkle

vault share(nom, cle_priv_rsa_proprio, [nouvelles_cles_pub])
  Redéchiffre la clé de fichier et la rechiffre pour les nouveaux destinataires
```

---


# 12. Analyse de securite -- Audit de l'application

## 12.1 Modele de menaces

### Biens a proteger

| Bien | Description |
|---|---|
| Contenu des messages | Les messages echanges entre Alice et Bob ne doivent etre lisibles que par eux. |
| Identite des utilisateurs | On doit pouvoir verifier qu'un message vient bien d'Alice et non de Mallory. |
| Cles privees | Si une cle privee est compromise, toutes les communications futures (signature) sont compromises. |
| Mots de passe | Le serveur stocke des haches sales ; meme si la base fuit, les mots de passe ne doivent pas etre retrouves. |
| Fichiers du coffre-fort | Seuls les destinataires autorises peuvent dechiffrer un fichier. |
| Integrite des fichiers | Un fichier ne doit pas etre modifie silencieusement. |

### Attaquants et capacites

| Attaquant | Capacites | Objectif |
|---|---|---|
| Eve (passif) | Ecoute le canal reseau, enregistre les chiffres. | Dechiffrer des messages passes ou futurs. |
| Mallory (actif) | Modifie, rejoue ou injecte des messages en transit. | Alterer un message, se faire passer pour Alice. |
| Serveur malveillant | Acces a la base de donnees, aux chiffres, aux certificats. | Retrouver les cles ou les messages. |
| Poste vole | Acces physique au disque, aux fichiers de configuration. | Extraire la cle privee ou le mot de passe. |
| Attaquant interne | Destinataire legitime qui tente d'acceder a d'autres fichiers. | Lire des fichiers dont il n'est pas destinataire. |

---

## 12.2 Attaques realisees : principe, faille, contre-mesure

### lab/attaques_rsa.py

**Attaque 1 -- Factorisation Pollard-rho (module 64 bits)**

Principe : l'algorithme de Pollard-rho exploite le paradoxe des anniversaires dans Zn pour trouver un facteur non trivial de n en O(n^(1/4)) operations. Deux sequences xi = f(xi-1) et yi = f(f(yi-1)) avancent a vitesse differente ; quand pgcd(|xi - yi|, n) est non trivial, on a trouve un facteur.

Faille exploitee : un module RSA de 64 bits est trivial a factoriser en quelques millisecondes. La securite RSA repose sur la difficulte de factoriser n = p*q ; si n est trop petit, cette hypothese tombe.

Contre-mesure dans CryptoVault : les modules RSA sont de 1024 bits minimum (2048 recommandes en production). Le meilleur record public de factorisation est RSA-250 (829 bits, 2020).

---

**Attaque 2 -- Malleabilite du RSA textbook**

Principe : si C = M^e mod n, alors (k^e * C) mod n = (kM)^e mod n. En envoyant k^e * C a un oracle de dechiffrement, l'attaquant obtient kM et deduit M = kM / k, sans avoir eu C dechiffre directement.

Faille exploitee : absence de padding -- le RSA textbook est deterministe et malleable.

Contre-mesure dans CryptoVault : toutes les operations RSA utilisent OAEP (RFC 8017). OAEP integre une graine aleatoire, rendant la malleabilite impossible.

---

**Attaque 3 -- Racine cubique entiere (e=3, sans padding)**

Principe : si e = 3 et M^3 < n (pas de reduction modulaire), alors C = M^3 est un simple cube entier. La racine cubique entiere de C redonne M directement, sans connaitre la cle privee.

Faille exploitee : pas de padding aleatoire + message petit relativement a n.

Contre-mesure dans CryptoVault : OAEP ajoute systematiquement une graine aleatoire de 32 octets. M devient M' = OAEP(M, graine), toujours proche de la taille de n.

---

**Attaque 4 -- Facteur premier commun entre deux modules**

Principe : si n1 = p*q1 et n2 = p*q2 partagent le premier p, alors pgcd(n1, n2) = p, calculable en une milliseconde. Les deux cles privees sont immediatement retrouvees.

Faille exploitee : PRNG de mauvaise qualite au demarrage. Observe en 2012 sur des milliers de routeurs embarques.

Contre-mesure dans CryptoVault : generation de premiers avec HMAC_DRBG reensemence depuis os.urandom. Chaque premier utilise 256 bits d'entropie reelle.

---

### lab/attaques_dh.py

**Attaque 5 -- Homme du milieu (MITM) sur DH non authentifie**

Principe : Mallory intercepte A = g^a, envoie M = g^m a Bob. Il intercepte B = g^b, envoie M a Alice. Alice et Bob partagent chacun un secret different avec Mallory, qui lit et modifie tous les messages.

Faille exploitee : DH seul n'authentifie pas l'identite des parties.

Contre-mesure dans CryptoVault : chaque partie signe sa valeur ECDHE avec sa cle longue terme (ECDSA). L'autre verifie la signature contre le certificat PKI. Mallory ne peut pas signer avec la cle d'Alice.

---

**Attaque 6 -- Baby-step Giant-step (BSGS) sur petit premier**

Principe : BSGS resout le logarithme discret h = g^x mod p en O(sqrt(p-1)) operations et espace, contre O(p) pour la force brute.

Faille exploitee : groupe DH de petit ordre.

Contre-mesure dans CryptoVault : groupe MODP-2048 (RFC 3526), sqrt(p-1) environ 2^1024, totalement hors de portee.

---

### lab/attaques_ecc.py

**Attaque 7 -- Nonce ECDSA reutilise**

Principe : si k est identique pour deux signatures (r1 = r2) :
- s1 - s2 = k^(-1)(z1 - z2) mod n
- k = (z1 - z2) * (s1 - s2)^(-1) mod n
- d = (s1*k - z1) * r^(-1) mod n

La cle privee est retrouvee algebriquement en quelques microsecondes.

Faille exploitee : k constant (Sony PS3, 2010) ou k genere par un PRNG faible (vols de Bitcoin 2013).

Contre-mesure dans CryptoVault : nonce deterministe RFC 6979. k est derive de HMAC-SHA256(d, h(message)). Deux messages differents donnent obligatoirement deux k differents.

---

### lab/attaques_sym.py

**Attaque 8 -- Motif visible en mode ECB**

Principe : en ECB, chaque bloc de 16 octets est chiffre independamment. Deux blocs en clair identiques produisent deux blocs chiffres identiques -- les contours d'une image restent visibles.

Faille exploitee : absence de dependance entre les blocs.

Contre-mesure dans CryptoVault : AES-GCM mode par defaut. Le compteur change a chaque bloc.

---

**Attaque 9 -- Bit-flipping sur CBC non authentifie**

Principe : Mi = D(Ci) XOR Ci-1. Modifier le bit j de Ci-1 flippe exactement le bit j de Mi de facon previsible. L'attaquant peut modifier un champ precis du message dechiffre (ex. admin=0 vers admin=1).

Faille exploitee : chiffrement sans authentification.

Contre-mesure dans CryptoVault : AES-GCM calcule un tag GHASH sur l'integralite du chiffre. Toute modification invalide le tag.

---

**Attaque 10 -- Reutilisation de la cle OTP**

Principe : si C1 = M1 XOR K et C2 = M2 XOR K, alors C1 XOR C2 = M1 XOR M2. La cle s'annule.

Faille exploitee : cle utilisee deux fois.

Contre-mesure dans CryptoVault : AES-GCM avec un nonce unique de 12 octets par message. La reutilisation d'un nonce en GCM est catastrophique, donc le nonce est genere par HMAC_DRBG et jamais reutilise.

---

### lab/attaques_prng.py

**Attaque 11 -- Casser un LCG (retrouver a et c)**

Principe : avec m connu et trois sorties consecutives x0, x1, x2 :
a = (x2 - x1) * inverse(x1 - x0) mod m
c = x1 - a*x0 mod m
L'etat interne est entierement reconstruit.

Faille exploitee : structure lineaire totalement previsible.

Contre-mesure dans CryptoVault : HMAC_DRBG pour tout alea cryptographique. Les LCG ne sont presents qu'a titre pedagogique.

---

**Attaque 12 -- Clonage du Mersenne Twister (624 sorties)**

Principe : le tempering du MT est bijectif donc inversible. En observant 624 sorties de 32 bits, on inverse le tempering sur chacune pour reconstituer mt[] en entier. Le generateur clone predit ensuite toutes les sorties suivantes avec 100% de precision.

Faille exploitee : etat interne de taille finie (624 x 32 = 19968 bits) et transformation inversible.

Contre-mesure dans CryptoVault : HMAC_DRBG. L'etat interne (K, V) n'est pas directement observable dans les sorties (HMAC est une fonction a sens unique).

---

## 12.3 Limites honetes du prototype

**Canaux auxiliaires (timing).** Les multiplications modulaires Python ont un temps d'execution variable selon les valeurs. Un attaquant local pourrait extraire des bits de la cle privee par analyse temporelle. Les bibliotheques de production utilisent des operations a temps constant et du blinding.

**Gestion memoire non securisee.** Python ne garantit pas l'effacement immediat des objets supprimes. Une cle privee ayant transite en memoire peut rester accessible dans le heap.

**Pas d'audit externe.** Le code n'a pas ete relu par des experts en securite. Des vulnerabilites subtiles peuvent exister : validation incomplete des entrees (points ECC invalides), oracle de padding sur OAEP, erreurs dans la verification de la chaine PKI.

**Format de certificat non interoperable.** Le format JSON maison n'est pas compatible avec X.509 (RFC 5280). Un deploiement reel utiliserait la bibliotheque cryptography de Python (pyca).

**Protocole reseau absent.** L'application est simulee en memoire. Un vrai protocole necessite la gestion des timeouts, reconnexions, protection contre le deni de service, etc.

**Pourquoi on n'utilise jamais ce code en production.**

Le principe de Kerckhoffs est que la securite repose sur le secret de la cle, pas de l'algorithme. Les algorithmes standards (AES, RSA, P-256) ont ete analyses pendant des decennies par des milliers de cryptanalystes. Nos implementations, codees en quelques heures, n'ont beneficie d'aucune de cette analyse. L'histoire montre que meme des equipes expertes font des erreurs catastrophiques : Netscape SSL en 1995 (graine PRNG previsible), Debian OpenSSL en 2008 (entropie nulle), la PS3 en 2010 (nonce constant). "Never roll your own crypto" n'est pas un slogan, c'est une lecon apprise a coups de failles reelles.

---

# 13. Menace quantique et strategie de migration

## 13.1 Impact sur chaque primitive

| Primitive | Algorithme menaçant | Impact | Statut |
|---|---|---|---|
| RSA-1024/2048 | Shor | Factorise en temps polynomial | Vulnerable a terme |
| DH MODP-2048 | Shor | Log discret en temps polynomial | Vulnerable a terme |
| ECDH P-256 / ECDSA | Shor | Log discret elliptique en temps polynomial | Vulnerable a terme |
| AES-128 | Grover | Securite reduite a 2^64 | Passer a AES-256 |
| AES-256 | Grover | Securite reduite a 2^128 | Acceptable |
| SHA-256 | Grover | Resistance collisions 2^85 | Passer a SHA-384 |
| SHA-384 | Grover | Resistance collisions 2^128 | Sur |
| HMAC-SHA256 | Grover | Impact negligeable sur HMAC | Acceptable |
| HMAC_DRBG | -- | Aucun impact direct | Sur |

L'algorithme de Shor, s'il est execute sur un ordinateur quantique de taille suffisante, casse RSA, DH et ECC en temps polynomial. L'algorithme de Grover accelere quadratiquement la recherche exhaustive : une cle de n bits offre alors n/2 bits de securite effective.

## 13.2 Strategie de migration

**Immediatement :**
- Passer AES-128 vers AES-256 pour tous les chiffrements.
- Passer SHA-256 vers SHA-384 pour les signatures et les certificats.
- Adopter l'agilite cryptographique : les algorithmes sont des parametres de configuration, pas des constantes.

**A court terme (deploiements hybrides) :**

Le NIST a standardise en 2024 les premiers algorithmes post-quantiques :
- ML-KEM (ex-Kyber) pour l'echange de cles, base sur les reseaux euclidiens.
- ML-DSA (ex-Dilithium) pour les signatures numeriques.
- SLH-DSA (ex-SPHINCS+) pour les signatures a base de haches.

La strategie recommandee est le deploiement hybride : combiner X25519 + ML-KEM pour l'echange de cles. Si l'un des deux est casse (quantique ou faille classique), l'autre continue de proteger.

**Harvest now, decrypt later :**

Un attaquant peut enregistrer aujourd'hui des communications chiffrees avec RSA/ECDH et les dechiffrer dans 10-15 ans. Pour les donnees a longue duree de confidentialite, la migration vers des algorithmes post-quantiques est urgente maintenant.

Dans CryptoVault, la migration se ferait en :
1. Remplacant ecdh_generer_cle(P256) par une paire hybride X25519 + ML-KEM.
2. Remplacant ecdsa_signer par ML-DSA dans les certificats PKI.
3. Conservant AES-256-GCM inchange (non menace).
4. Augmentant les sorties de hachage a SHA-384 pour les signatures.

# 14. Tableau de traçabilité complet

| Fonctionnalité | Modules | Chapitres cours |
|---|---|---|
| Hash de fichier (MD5, SHA-1, SHA-256, SHA3-256) | hashing | 1 |
| Vérification d'intégrité | hashing | 1 |
| Effet avalanche | hashing | 1 |
| HMAC-SHA256 (RFC 2104) | hashing | 1 |
| Stockage mots de passe (PBKDF2 + sel) | hashing | 1 |
| Arbre de Merkle + preuve d'appartenance | hashing | 1 |
| Attaque anniversaire (SHA-256 tronqué) | hashing, lab/ | 1 |
| PGCD, Euclide étendu | numtheory | 2 |
| Inverse modulaire | numtheory | 2 |
| Exponentiation modulaire (square-and-multiply) | numtheory | 2 |
| CRT (k congruences) | numtheory | 2 |
| Test de Miller-Rabin | numtheory | 2 |
| Génération de premiers aléatoires | numtheory | 2 |
| Indicatrice d'Euler, théorème d'Euler | numtheory | 2 |
| Génération de clés RSA | rsa, numtheory | 2, 3 |
| Chiffrement RSA-OAEP | rsa | 3 |
| Déchiffrement RSA avec CRT | rsa, numtheory | 2, 3 |
| Signature RSA | rsa | 3 |
| Chiffrement hybride RSA + AES-GCM | rsa, symmetric | 3, 6 |
| Attaques RSA (Pollard-rho, malléabilité, racine cubique, PGCD) | lab/attaques_rsa | 3 |
| Diffie-Hellman (MODP-2048, groupe jouet) | dh, numtheory | 2, 4 |
| HKDF (RFC 5869) | dh, hashing | 1, 4 |
| Dérivation de clés de session | dh | 4 |
| Attaque MITM + contre-mesure signatures | lab/attaques_dh | 4 |
| Confidentialité persistante (PFS) | dh, app/ | 4 |
| BSGS sur logarithme discret | lab/attaques_dh | 4 |
| Courbe elliptique (addition, doublement, multiplication) | ecc | 5 |
| ECDH (P-256, courbe jouet) | ecc | 5 |
| ECDSA + nonce déterministe RFC 6979 | ecc, hashing | 1, 5 |
| Attaque nonce réutilisé ECDSA | lab/attaques_ecc | 5 |
| Chiffrements classiques (César, Vigenère) + cryptanalyse | symmetric | 6 |
| Masque jetable (OTP) + attaque réutilisation | symmetric, lab/ | 6 |
| AES-ECB, CBC, CTR, GCM | symmetric | 6 |
| Padding PKCS#7 | symmetric | 6 |
| Attaque bit-flipping CBC | lab/attaques_sym | 6 |
| Démonstration ECB (motif visible) | lab/attaques_sym | 6 |
| AC hiérarchique, émission certificats | pki | 7 |
| Vérification chaîne de certification | pki | 7 |
| CRL + révocation | pki | 7 |
| Keystore chiffré (AES-GCM + PBKDF2) | pki, symmetric, hashing | 1, 6, 7 |
| LCG (cours + 32 bits) | prng | 8 |
| Mersenne Twister MT19937 | prng | 8 |
| HMAC_DRBG (NIST SP 800-90A) | prng, hashing | 1, 8 |
| Tests statistiques (monobit, runs, chi²) | prng | 8 |
| Attaque LCG (retrouver a, c) | lab/attaques_prng | 8 |
| Clonage MT19937 (inversion tempering) | lab/attaques_prng | 8 |
| Inscription utilisateur (messagerie) | app/server, hashing, pki | 1, 7 |
| Handshake ECDHE authentifié | app/, ecc, dh, pki | 4, 5, 7 |
| Messagerie AES-GCM anti-rejeu | app/, symmetric | 6 |
| Coffre-fort (add/get/list/share) | app/vault, rsa, ecc, symmetric, hashing | 1, 3, 5, 6 |

---

# 15. Difficultés rencontrées

**Compatibilité Python 3.14.** Le Mersenne Twister de Python 3.2+ hache la graine avant l'initialisation (state version 3), ce qui rend les sorties incompatibles avec les implémentations directes de MT19937. Nous avons adapté le test pour vérifier les propriétés plutôt que les valeurs exactes.

**Taille minimale pour OAEP.** RSA-OAEP avec SHA-256 nécessite un module d'au moins 2·32 + 2 = 66 octets (528 bits). Les tests initiaux avec des modules de 512 bits échouaient car les modules générés pouvaient avoir 511 bits. Résolu en utilisant des modules de 512+512 = 1024 bits minimum.

**Pytest et fonctions préfixées test_.** Les fonctions `test_fermat`, `test_miller_rabin` dans numtheory.py et `test_monobit` etc. dans prng.py étaient collectées comme des tests pytest. Résolu en les renommant (`fermat_probable_premier`, `stat_monobit`) et en ajoutant un `pytest.ini` limitant la collecte au dossier `tests/`.

**Écriture de fichiers verrouillés.** Sous Windows, les fichiers ouverts dans l'éditeur ne peuvent pas être réécrits directement par Python. Résolu en passant par un script intermédiaire qui écrit le fichier avec `open(..., 'w')`.

**DH sur groupe jouet (p=23).** La validation des valeurs DH (rejet de 1 et p-1) causait des boucles infinies ou des erreurs quand le générateur produisait ces valeurs légitimes (g^22 = 1 mod 23 par Fermat). Résolu en faisant recommencer la génération si A ∉ ]1, p-1[.

---

# 16. Conclusion

Ce projet a permis d'implémenter de bout en bout les neuf modules du cours et de les assembler en une application cohérente. Les 254 tests unitaires et d'intégration valident chaque primitive sur des vecteurs officiels (RFC 4231, RFC 5869, FIPS 186, cours).

Les attaques pédagogiques illustrent concrètement pourquoi chaque bonne pratique existe : le padding OAEP protège contre la malléabilité, le nonce déterministe RFC 6979 empêche la réutilisation catastrophique de k, AES-GCM détecte les modifications que CBC laisse passer, et HMAC_DRBG remplace le Mersenne Twister prédictible.

La menace quantique rend cette architecture vulnérable à moyen terme pour toutes les primitives à clé publique (RSA, DH, ECC). Une migration vers des schémas post-quantiques hybrides (X25519 + ML-KEM, ECDSA + ML-DSA) est la voie recommandée pour les systèmes à longue durée de vie.

---

*Références : RFC 2104, RFC 4231, RFC 5869, RFC 6979, RFC 8017, RFC 3526, RFC 5280 ; FIPS 180-4, FIPS 197, FIPS 186-5 ; NIST SP 800-90A, NIST SP 800-22.*
