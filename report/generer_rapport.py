"""
Generateur du rapport CryptoVault en .docx
Execution : python report/generer_rapport.py
Produit    : report/rapport_cryptovault.docx
"""
from docx import Document
from docx.shared import Pt, RGBColor, Inches, Cm
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.style import WD_STYLE_TYPE
from docx.oxml.ns import qn
from docx.oxml import OxmlElement
import re, os

doc = Document()

# ── Marges ──────────────────────────────────────────────────────────────────
for section in doc.sections:
    section.top_margin    = Cm(2.5)
    section.bottom_margin = Cm(2.5)
    section.left_margin   = Cm(2.5)
    section.right_margin  = Cm(2.5)

# ── Styles de base ───────────────────────────────────────────────────────────
normal = doc.styles['Normal']
normal.font.name = 'Calibri'
normal.font.size = Pt(11)

for h_name, size, bold in [
    ('Heading 1', 16, True),
    ('Heading 2', 13, True),
    ('Heading 3', 12, True),
]:
    s = doc.styles[h_name]
    s.font.size = Pt(size)
    s.font.bold = bold
    s.font.color.rgb = RGBColor(0x1F, 0x49, 0x7D)

# ── Helpers ──────────────────────────────────────────────────────────────────
def add_title(text, level):
    doc.add_heading(text, level=level)

def add_para(text, bold=False, italic=False, size=11):
    p = doc.add_paragraph()
    run = p.add_run(text)
    run.bold = bold
    run.italic = italic
    run.font.size = Pt(size)
    return p

def add_bullet(text):
    p = doc.add_paragraph(style='List Bullet')
    p.add_run(text)

def add_code(text):
    p = doc.add_paragraph()
    p.style = doc.styles['Normal']
    run = p.add_run(text)
    run.font.name = 'Courier New'
    run.font.size = Pt(9)
    shading = OxmlElement('w:shd')
    shading.set(qn('w:fill'), 'F2F2F2')
    shading.set(qn('w:val'), 'clear')
    p._p.get_or_add_pPr().append(shading)

def add_table(headers, rows):
    t = doc.add_table(rows=1 + len(rows), cols=len(headers))
    t.style = 'Table Grid'
    hdr = t.rows[0].cells
    for i, h in enumerate(headers):
        hdr[i].text = h
        for run in hdr[i].paragraphs[0].runs:
            run.bold = True
    for r_idx, row in enumerate(rows):
        cells = t.rows[r_idx + 1].cells
        for c_idx, val in enumerate(row):
            cells[c_idx].text = str(val)
    doc.add_paragraph()

def page_break():
    doc.add_page_break()

# ════════════════════════════════════════════════════════════════════════════
# PAGE DE TITRE
# ════════════════════════════════════════════════════════════════════════════
p = doc.add_paragraph()
p.alignment = WD_ALIGN_PARAGRAPH.CENTER
run = p.add_run("CryptoVault")
run.font.size = Pt(28)
run.font.bold = True
run.font.color.rgb = RGBColor(0x1F, 0x49, 0x7D)

doc.add_paragraph()
p2 = doc.add_paragraph()
p2.alignment = WD_ALIGN_PARAGRAPH.CENTER
p2.add_run("Plateforme de messagerie chiffrée et coffre-fort sécurisé\n"
           "Rapport de projet — Cours Cryptographie 20 h\n"
           "Octobre 2026").font.size = Pt(13)

doc.add_paragraph()
page_break()

# ════════════════════════════════════════════════════════════════════════════
# 1. INTRODUCTION
# ════════════════════════════════════════════════════════════════════════════
add_title("1. Introduction", 1)
add_para(
    "Ce rapport présente la conception et l'implémentation de CryptoVault, "
    "une plateforme de messagerie chiffrée de bout en bout et de coffre-fort "
    "de fichiers sécurisé. Le projet a été réalisé dans le cadre du cours de "
    "cryptographie (20 heures) et met en oeuvre les primitives suivantes : "
    "fonctions de hachage, arithmétique modulaire, RSA, Diffie-Hellman, courbes "
    "elliptiques, cryptographie symétrique, PKI et générateurs pseudo-aléatoires."
)
add_para(
    "L'objectif pédagogique est double : implémenter chaque brique à la main pour "
    "en comprendre le fonctionnement interne, puis illustrer par des attaques sur "
    "nos propres implémentations jouets pourquoi les bonnes pratiques existent."
)
add_para(
    "Note de sécurité : conformément aux consignes, ce prototype est un exercice "
    "d'apprentissage. Les implémentations manuelles de RSA, DH et ECC ne résistent "
    "pas aux attaques par canaux auxiliaires et ne sont pas destinées à protéger "
    "des données réelles.",
    italic=True
)

# ════════════════════════════════════════════════════════════════════════════
# 2. ARCHITECTURE
# ════════════════════════════════════════════════════════════════════════════
add_title("2. Architecture générale", 1)
add_code(
    "cryptovault/\n"
    "├── cryptolib/      bibliothèque cryptographique (modules 1-8)\n"
    "├── app/            application intégrée (module 9)\n"
    "├── lab/            scripts d'attaques pédagogiques\n"
    "├── tests/          254 tests unitaires et d'intégration\n"
    "└── report/         ce rapport"
)
add_para(
    "Les modules cryptolib sont indépendants et réutilisables. L'application (app/) "
    "les assemble en un protocole cohérent. Les scripts lab/ démontrent les failles "
    "quand les primitives sont mal utilisées."
)
add_title("Contraintes d'implémentation respectées", 3)
add_bullet("Modules numtheory, rsa, dh, ecc : zéro bibliothèque cryptographique.")
add_bullet("AES : pycryptodome autorisé (modes ECB, CBC, CTR, GCM).")
add_bullet("Fonctions de hachage : hashlib de la bibliothèque standard.")
add_bullet("Aucune clé ni secret en clair dans le code ou le dépôt.")

page_break()

# ════════════════════════════════════════════════════════════════════════════
# 3-10. MODULES
# ════════════════════════════════════════════════════════════════════════════
modules = [
    ("3. Module 1 — Fonctions de hachage", [
        ("3.1 Implémentation",
         "La fonction calculer_empreintes calcule MD5, SHA-1, SHA-256 et SHA3-256 "
         "en une seule passe par blocs de 4096 octets. HMAC-SHA256 est implémenté "
         "manuellement selon la RFC 2104 : padding de la clé à 64 octets, XOR avec "
         "ipad (0x36) et opad (0x5C), double hachage imbriqué. "
         "Le stockage des mots de passe utilise PBKDF2-HMAC-SHA256 avec 260 000 "
         "itérations et un sel aléatoire de 16 octets par utilisateur."),
        ("3.2 Arbre de Merkle",
         "L'arbre utilise la convention de préfixe (0x00 feuilles, 0x01 noeuds) "
         "conforme à Certificate Transparency. Cela empêche les attaques par second "
         "préimage sur la structure de l'arbre."),
        ("3.3 Résultats — attaque anniversaire (SHA-256 tronqué 32 bits)",
         "Essais théoriques 2^16 = 65 536. Essais observés : 55 000-75 000. "
         "Durée : < 1 seconde. Cohérent avec le paradoxe des anniversaires."),
    ]),
    ("4. Module 2 — Arithmétique modulaire", [
        ("4.1 Euclide étendu et inverse modulaire",
         "egcd(a, b) retourne (g, u, v) tels que a·u + b·v = g. Implémentation "
         "itérative. L'inverse modulaire en découle : si g = 1, u mod n est l'inverse."),
        ("4.2 Exponentiation modulaire — square-and-multiply",
         "Implémentée sans pow(a, e, n). O(log e) multiplications. "
         "Notre expmod : ~0.8 s pour 5 appels sur 2048 bits. "
         "pow() natif : ~0.002 s. Écart dû aux optimisations CPython/GMP."),
        ("4.3 Miller-Rabin et génération de premiers",
         "Avec k=40 bases, probabilité d'erreur ≤ 4^(-40) ≈ 10^(-24). "
         "Rejette correctement les nombres de Carmichael (561, 1105, 1729). "
         "Nombre de candidats testés conforme au théorème des nombres premiers : "
         "~ln(2^k)/2 candidats pour des premiers de k bits."),
    ]),
    ("5. Module 3 — RSA", [
        ("5.1 Génération et accélération CRT",
         "Modules de 1024 bits (2048 recommandés). e = 65537 = 2^16 + 1. "
         "Déchiffrement CRT ~4× plus rapide : calcul modulo p et q séparément, "
         "recombinaison via la formule de Garner."),
        ("5.2 Padding OAEP (RFC 8017)",
         "MGF1 avec SHA-256. Graine aléatoire de 32 octets. Sécurité CCA2 prouvée. "
         "Longueur max du message : k - 2·hLen - 2 = 62 octets pour module 1024 bits."),
        ("5.3 Chiffrement hybride",
         "Clé de session AES-256 chiffrée par RSA-OAEP. Données chiffrées par "
         "AES-256-GCM. Permet de traiter des fichiers de taille arbitraire."),
    ]),
    ("6. Module 4 — Diffie-Hellman", [
        ("6.1 Paramètres et HKDF",
         "Groupe MODP-2048 (RFC 3526). HKDF (RFC 5869) validé sur les vecteurs "
         "officiels. Deux clés dérivées indépendantes : chiffrement (info=enc) "
         "et authentification (info=auth)."),
        ("6.2 Confidentialité persistante (PFS)",
         "Clés éphémères effacées après chaque session. Compromission ultérieure "
         "de la clé longue terme sans impact sur les sessions passées."),
    ]),
    ("7. Module 5 — Courbes elliptiques", [
        ("7.1 Implémentation",
         "Loi de groupe sur Fp (Weierstrass). Double-and-add. "
         "Validé sur la courbe jouet du cours : 18 multiples de G=(5,1) et 19G=∞ "
         "tous corrects. Courbes P-256 et secp256k1 : n·G = ∞ vérifié."),
        ("7.2 ECDSA + RFC 6979",
         "Nonce déterministe : k dérivé de HMAC-SHA256(d, h(message)). "
         "Deux messages différents → deux k différents, réutilisation impossible."),
        ("7.3 Comparaison RSA vs ECC",
         "P-256 : clé 256 bits, signature ~72 octets, sécurité 128 bits. "
         "RSA-3072 : module 3072 bits, signature 384 octets, sécurité 128 bits. "
         "ECC nettement plus compact, idéal pour les systèmes embarqués."),
    ]),
    ("8. Module 6 — Cryptographie symétrique", [
        ("8.1 Chiffrements classiques",
         "César : force brute 25 clés, cassé en < 1 ms. "
         "Vigenère : cassé par IC sur textes français de 100+ caractères."),
        ("8.2 Modes AES",
         "ECB : blocs identiques → chiffrés identiques (faille). "
         "CBC : chaînage mais vulnerable au bit-flipping sans authentification. "
         "CTR : chiffrement par flot, parallélisable. "
         "GCM (mode par défaut) : AEAD, toute modification détectée."),
    ]),
    ("9. Module 7 — PKI", [
        ("9.1 Hiérarchie de confiance",
         "AC Racine (auto-signée) → AC Intermédiaire → Certificats utilisateurs. "
         "Format JSON maison inspiré X.509 v3. Signature RSA sur le corps du certificat."),
        ("9.2 Révocation et keystore",
         "CRL signée par l'AC intermédiaire. "
         "Keystore : clé privée chiffrée AES-256-GCM + PBKDF2-HMAC-SHA256 "
         "(200 000 itérations, sel aléatoire). Rotation de mot de passe sans exposer la clé."),
    ]),
    ("10. Module 8 — Générateurs pseudo-aléatoires", [
        ("10.1 LCG et MT19937",
         "LCG : vecteur du cours (m=16, a=5, c=3) validé. MT19937 : déterministe, "
         "période 2^19937-1. Aucun des deux ne doit être utilisé pour la cryptographie."),
        ("10.2 HMAC_DRBG (NIST SP 800-90A)",
         "Basé sur HMAC-SHA256. Réensemencé depuis os.urandom. "
         "Backtracking resistance : sorties passées opaques même si K fuite."),
        ("10.3 Tests statistiques",
         "Monobit, runs et chi² appliqués aux trois générateurs. "
         "MT et HMAC_DRBG passent tous les tests. "
         "LCG 32 bits passe les tests de base mais reste prédictible — "
         "illustration que les tests statistiques ne prouvent pas la sécurité."),
    ]),
]

for title, sections in modules:
    add_title(title, 1)
    for sub_title, content in sections:
        add_title(sub_title, 2)
        add_para(content)

page_break()

# ════════════════════════════════════════════════════════════════════════════
# 11. APPLICATION INTEGREE
# ════════════════════════════════════════════════════════════════════════════
add_title("11. Module 9 — Application intégrée", 1)

add_title("11.1 Messagerie — protocole TLS simplifié", 2)
add_para("Inscription : génération de clés ECC, certificat PKI, mot de passe PBKDF2 salé.")
add_para("Handshake ECDHE :")
add_bullet("Le serveur génère une paire éphémère et signe sa valeur avec sa clé longue terme.")
add_bullet("Le client vérifie la chaîne PKI et la signature, envoie sa part signée.")
add_bullet("Secret partagé ECDHE → HKDF → deux clés AES-256 (chiffrement + auth).")
add_bullet("Clés éphémères effacées (PFS).")
add_para("Messages : AES-256-GCM avec numéros de séquence anti-rejeu. "
         "Toute modification du chiffré est détectée par le tag GCM.")

add_title("11.2 Coffre-fort de fichiers", 2)
add_bullet("add : clé AES-256 aléatoire (HMAC_DRBG) + AES-GCM + RSA-OAEP par destinataire + Merkle + ECDSA.")
add_bullet("get : vérifie signature → RSA-OAEP → AES-GCM → Merkle.")
add_bullet("share : redéchiffre la clé de session et la rechiffre pour les nouveaux destinataires.")
add_bullet("list + preuve d'appartenance Merkle.")

page_break()

# ════════════════════════════════════════════════════════════════════════════
# 12. ANALYSE DE SECURITE
# ════════════════════════════════════════════════════════════════════════════
add_title("12. Analyse de sécurité — Audit de l'application", 1)

add_title("12.1 Modèle de menaces", 2)
add_title("Biens à protéger", 3)
add_table(
    ["Bien", "Description"],
    [
        ["Contenu des messages", "Lisibles uniquement par les destinataires."],
        ["Identité des utilisateurs", "Vérifier qu'un message vient bien d'Alice."],
        ["Clés privées", "Compromission = perte de confidentialité ou d'authenticité."],
        ["Mots de passe", "Stockés hachés salés, retrouvables même si la base fuit."],
        ["Fichiers du coffre-fort", "Seuls les destinataires autorisés déchiffrent."],
        ["Intégrité des fichiers", "Aucune modification silencieuse."],
    ]
)
add_title("Attaquants", 3)
add_table(
    ["Attaquant", "Capacités", "Objectif"],
    [
        ["Ève (passif)", "Écoute le réseau, enregistre les chiffrés.", "Déchiffrer des messages."],
        ["Mallory (actif)", "Modifie, rejoue ou injecte des messages.", "Altérer un message, usurper une identité."],
        ["Serveur malveillant", "Accès à la base, aux chiffrés, aux certificats.", "Retrouver les clés ou messages."],
        ["Poste volé", "Accès physique au disque.", "Extraire la clé privée ou le mot de passe."],
        ["Attaquant interne", "Destinataire légitime.", "Accéder à des fichiers dont il n'est pas destinataire."],
    ]
)

add_title("12.2 Attaques réalisées : principe, faille, contre-mesure", 2)

attaques = [
    ("lab/attaques_rsa.py — Attaque 1 : Factorisation Pollard-rho (64 bits)",
     "Pollard-rho exploite le paradoxe des anniversaires dans Zn pour trouver un facteur "
     "non trivial en O(n^1/4). Durée observée : < 5 ms.",
     "Module RSA trop petit.",
     "Modules ≥ 1024 bits dans CryptoVault (2048 recommandés en production)."),
    ("lab/attaques_rsa.py — Attaque 2 : Malléabilité RSA textbook",
     "Si C = M^e mod n, alors (k^e · C) = (kM)^e mod n. Un oracle de déchiffrement "
     "sur le chiffré modifié donne kM, d'où M = kM / k.",
     "Absence de padding.",
     "RSA-OAEP (RFC 8017) systématique."),
    ("lab/attaques_rsa.py — Attaque 3 : Racine cubique entière (e=3)",
     "Si M^3 < n, aucune réduction modulaire. La racine cubique entière de C = M^3 "
     "redonne M sans connaître la clé privée.",
     "Pas de padding + message petit.",
     "OAEP ajoute 32 octets aléatoires, M' est toujours proche de la taille de n."),
    ("lab/attaques_rsa.py — Attaque 4 : Facteur commun (pgcd)",
     "Si n1 = p·q1 et n2 = p·q2 partagent p, pgcd(n1,n2) = p en 1 ms. "
     "Observé en 2012 sur des milliers de routeurs.",
     "PRNG défaillant au démarrage.",
     "HMAC_DRBG + os.urandom pour la génération de tous les premiers."),
    ("lab/attaques_dh.py — Attaque 5 : MITM sur DH non authentifié",
     "Mallory intercepte A = g^a et B = g^b, envoie M = g^m aux deux parties. "
     "Deux secrets distincts établis, Mallory lit tout.",
     "DH seul n'authentifie pas les parties.",
     "Chaque partie signe sa valeur ECDHE avec sa clé longue terme (ECDSA)."),
    ("lab/attaques_dh.py — Attaque 6 : BSGS sur petit premier",
     "Baby-step Giant-step : complexité O(sqrt(p-1)). "
     "Sur 30 bits : < 50 ms.",
     "Groupe DH de petit ordre.",
     "Groupe MODP-2048, sqrt(p-1) ≈ 2^1024."),
    ("lab/attaques_ecc.py — Attaque 7 : Nonce ECDSA réutilisé",
     "Si r1 = r2 (même k) : k = (z1-z2)/(s1-s2) mod n, puis d = (s1·k-z1)/r mod n. "
     "Clé privée retrouvée algébriquement. PS3 (2010), vols Bitcoin (2013).",
     "k constant ou généré par PRNG faible.",
     "Nonce déterministe RFC 6979 : k = HMAC(d, h(message))."),
    ("lab/attaques_sym.py — Attaque 8 : Motif ECB",
     "Blocs identiques en clair → blocs chiffrés identiques. "
     "Les contours d'une image restent visibles.",
     "Absence de dépendance inter-blocs en ECB.",
     "AES-GCM mode par défaut."),
    ("lab/attaques_sym.py — Attaque 9 : Bit-flipping CBC",
     "Mi = D(Ci) XOR Ci-1. Modifier Ci-1[j] flippe Mi[j] de façon prévisible. "
     "admin=0 → admin=1 sans connaître la clé.",
     "Chiffrement sans authentification.",
     "AES-GCM : tag GHASH invalide toute modification."),
    ("lab/attaques_sym.py — Attaque 10 : Réutilisation OTP",
     "C1 XOR C2 = M1 XOR M2. La clé s'annule.",
     "Clé utilisée deux fois.",
     "AES-GCM avec nonce HMAC_DRBG unique par message."),
    ("lab/attaques_prng.py — Attaque 11 : Casser un LCG",
     "Avec 3 sorties consécutives : a = (x2-x1)/(x1-x0) mod m, c = x1-a·x0 mod m. "
     "État interne entièrement reconstruit.",
     "Structure linéaire prévisible.",
     "HMAC_DRBG pour tout aléa cryptographique."),
    ("lab/attaques_prng.py — Attaque 12 : Cloner MT19937",
     "Le tempering est bijectif. 624 sorties suffisent à inverser et reconstruire "
     "mt[] en entier. Prédiction suivante : 100% de précision.",
     "État interne de taille finie, transformation inversible.",
     "HMAC_DRBG : état (K,V) opaque (HMAC à sens unique)."),
]

for titre, principe, faille, contre in attaques:
    add_title(titre, 3)
    add_para("Principe : " + principe)
    add_para("Faille : " + faille, bold=False, italic=True)
    add_para("Contre-mesure : " + contre)

add_title("12.3 Limites du prototype", 2)
limites = [
    ("Canaux auxiliaires (timing)",
     "Les multiplications modulaires Python ont un temps variable. Un attaquant local "
     "pourrait extraire des bits de clé privée par analyse temporelle. "
     "Les bibliothèques de production utilisent des opérations à temps constant et du blinding."),
    ("Gestion mémoire non sécurisée",
     "Python ne garantit pas l'effacement immédiat des objets supprimés. "
     "Une clé privée peut rester dans le heap après del."),
    ("Absence d'audit externe",
     "Le code n'a pas été relu par des experts en sécurité. Des vulnérabilités subtiles "
     "peuvent exister : validation des points ECC, oracle de padding, chaîne PKI."),
    ("Format de certificat non interopérable",
     "Format JSON maison, incompatible avec X.509 (RFC 5280). "
     "Un déploiement réel utiliserait la bibliothèque cryptography (pyca)."),
    ("Protocole réseau absent",
     "Application simulée en mémoire. Un vrai déploiement nécessite "
     "la gestion des timeouts, reconnexions, protection contre le DoS."),
]
for titre, texte in limites:
    add_para("• " + titre + " : " + texte)

add_title("12.4 Pourquoi ne jamais utiliser ce code en production", 2)
add_para(
    "Le principe de Kerckhoffs est que la sécurité repose sur le secret de la clé, "
    "pas de l'algorithme. Les algorithmes standards (AES, RSA, P-256) ont été analysés "
    "pendant des décennies. Nos implémentations, codées en quelques heures, n'ont bénéficié "
    "d'aucune de cette analyse. L'histoire montre que même des équipes expertes font des "
    "erreurs catastrophiques : Netscape SSL 1995 (graine PRNG prévisible), Debian OpenSSL "
    "2008 (entropie nulle), PS3 2010 (nonce constant). \"Never roll your own crypto\" "
    "n'est pas un slogan, c'est une leçon apprise à coups de failles réelles."
)

page_break()

# ════════════════════════════════════════════════════════════════════════════
# 13. MENACE QUANTIQUE
# ════════════════════════════════════════════════════════════════════════════
add_title("13. Menace quantique et stratégie de migration", 1)
add_title("13.1 Impact sur chaque primitive", 2)
add_table(
    ["Primitive", "Menace", "Impact", "Statut"],
    [
        ["RSA-2048",     "Shor", "Factorise en temps polynomial", "Vulnérable"],
        ["DH MODP-2048", "Shor", "Log discret en temps polynomial", "Vulnérable"],
        ["ECDH/ECDSA P-256", "Shor", "ECDLP en temps polynomial", "Vulnérable"],
        ["AES-128", "Grover", "Sécurité réduite à 2^64", "Passer à AES-256"],
        ["AES-256", "Grover", "Sécurité réduite à 2^128", "Acceptable"],
        ["SHA-256", "Grover", "Collisions : 2^85", "Passer à SHA-384"],
        ["SHA-384", "Grover", "Collisions : 2^128", "Sûr"],
        ["HMAC_DRBG", "—", "Aucun impact direct", "Sûr"],
    ]
)

add_title("13.2 Stratégie de migration", 2)
add_para("Immédiatement :", bold=True)
add_bullet("AES-128 → AES-256 pour tous les chiffrements.")
add_bullet("SHA-256 → SHA-384 pour les signatures et certificats.")
add_bullet("Agilité cryptographique : algorithmes en paramètres de configuration.")

add_para("À court terme — déploiements hybrides (NIST 2024) :", bold=True)
add_bullet("ML-KEM (ex-Kyber) pour l'échange de clés : X25519 + ML-KEM en parallèle.")
add_bullet("ML-DSA (ex-Dilithium) pour les signatures à la place d'ECDSA.")
add_bullet("SLH-DSA (ex-SPHINCS+) comme alternative à base de hachés.")

add_para("Harvest now, decrypt later :", bold=True)
add_para(
    "Un attaquant peut enregistrer aujourd'hui des communications chiffrées avec RSA/ECDH "
    "et les déchiffrer dans 10-15 ans. Pour les données à longue durée de confidentialité, "
    "la migration est urgente maintenant, avant que les ordinateurs quantiques pertinents "
    "n'existent."
)

add_para("Plan de migration pour CryptoVault :", bold=True)
add_bullet("Remplacer ecdh_generer_cle(P256) par une paire hybride X25519 + ML-KEM.")
add_bullet("Remplacer ecdsa_signer par ML-DSA dans les certificats PKI.")
add_bullet("Conserver AES-256-GCM inchangé (non menacé).")
add_bullet("Augmenter les sorties de hachage à SHA-384 pour les signatures.")

page_break()

# ════════════════════════════════════════════════════════════════════════════
# 14. TABLEAU DE TRACABILITE
# ════════════════════════════════════════════════════════════════════════════
add_title("14. Tableau de traçabilité", 1)
add_table(
    ["Fonctionnalité", "Modules", "Chapitres"],
    [
        ["Hash de fichier (MD5, SHA-1, SHA-256, SHA3-256)", "hashing", "1"],
        ["HMAC-SHA256 (RFC 2104)", "hashing", "1"],
        ["Stockage mots de passe (PBKDF2 + sel)", "hashing", "1"],
        ["Arbre de Merkle + preuve", "hashing", "1"],
        ["Attaque anniversaire", "hashing, lab/", "1"],
        ["PGCD, Euclide étendu, CRT", "numtheory", "2"],
        ["Inverse modulaire, expmod", "numtheory", "2"],
        ["Test Miller-Rabin, generate_prime", "numtheory", "2"],
        ["Génération de clés RSA", "rsa, numtheory", "2, 3"],
        ["RSA-OAEP, signature, CRT accéléré", "rsa", "3"],
        ["Chiffrement hybride RSA + AES-GCM", "rsa, symmetric", "3, 6"],
        ["Attaques RSA (Pollard, malléab., racine, pgcd)", "lab/attaques_rsa", "3"],
        ["Diffie-Hellman MODP-2048", "dh, numtheory", "2, 4"],
        ["HKDF (RFC 5869)", "dh, hashing", "1, 4"],
        ["Attaque MITM + contre-mesure", "lab/attaques_dh", "4"],
        ["Confidentialité persistante (PFS)", "dh, app/", "4"],
        ["BSGS sur logarithme discret", "lab/attaques_dh", "4"],
        ["Courbe elliptique (P-256, secp256k1, jouet)", "ecc", "5"],
        ["ECDH, ECDSA + RFC 6979", "ecc", "5"],
        ["Attaque nonce ECDSA réutilisé", "lab/attaques_ecc", "5"],
        ["Chiffrements classiques + cryptanalyse", "symmetric", "6"],
        ["OTP + attaque réutilisation", "symmetric, lab/", "6"],
        ["AES ECB/CBC/CTR/GCM, padding PKCS#7", "symmetric", "6"],
        ["Attaque bit-flipping CBC", "lab/attaques_sym", "6"],
        ["AC hiérarchique, certificats, CRL", "pki", "7"],
        ["Keystore chiffré (AES-GCM + PBKDF2)", "pki, symmetric, hashing", "1, 6, 7"],
        ["LCG, MT19937, HMAC_DRBG", "prng", "8"],
        ["Tests statistiques (monobit, runs, chi²)", "prng", "8"],
        ["Attaque LCG, clonage MT19937", "lab/attaques_prng", "8"],
        ["Inscription + handshake ECDHE signé", "app/, ecc, dh, pki", "4, 5, 7"],
        ["Messagerie AES-GCM anti-rejeu", "app/, symmetric", "6"],
        ["Coffre-fort (add/get/list/share)", "app/vault, rsa, ecc, symmetric, hashing", "1, 3, 5, 6"],
    ]
)

page_break()

# ════════════════════════════════════════════════════════════════════════════
# 15. DIFFICULTES RENCONTREES
# ════════════════════════════════════════════════════════════════════════════
add_title("15. Difficultés rencontrées", 1)
difficultes = [
    ("Compatibilité Python 3.14 et MT19937",
     "Python 3.2+ hash la graine avant l'initialisation du MT (state version 3), "
     "rendant les sorties incompatibles avec les implémentations directes. "
     "Résolution : tester les propriétés (déterminisme, 32 bits) plutôt que les valeurs exactes."),
    ("Taille minimale pour RSA-OAEP",
     "OAEP avec SHA-256 nécessite un module d'au moins 66 octets (528 bits). "
     "Les tests initiaux avec des modules de 512 bits échouaient. "
     "Résolution : utiliser des modules de 1024 bits minimum dans les tests."),
    ("Pytest et fonctions préfixées test_",
     "Les fonctions test_fermat, test_miller_rabin (numtheory) et test_monobit (prng) "
     "étaient collectées comme des tests pytest. "
     "Résolution : renommage en fermat_probable_premier, stat_monobit, etc."),
    ("DH sur groupe jouet (p=23)",
     "La validation des valeurs DH (rejet de 1 et p-1) causait des boucles infinies "
     "car g^22 ≡ 1 mod 23 par Fermat. "
     "Résolution : régénérer la paire éphémère si A ∉ ]1, p-1[."),
    ("Écriture de fichiers verrouillés (Windows)",
     "Sous Windows, les fichiers ouverts dans l'éditeur bloquent les écritures Python. "
     "Résolution : script Python intermédiaire avec open(..., 'w')."),
]
for titre, texte in difficultes:
    add_title(titre, 3)
    add_para(texte)

page_break()

# ════════════════════════════════════════════════════════════════════════════
# 16. CONCLUSION
# ════════════════════════════════════════════════════════════════════════════
add_title("16. Conclusion", 1)
add_para(
    "Ce projet a permis d'implémenter de bout en bout les neuf modules du cours "
    "et de les assembler en une application cohérente. Les 254 tests unitaires et "
    "d'intégration valident chaque primitive sur des vecteurs officiels "
    "(RFC 4231, RFC 5869, FIPS 186, cours)."
)
add_para(
    "Les douze attaques pédagogiques illustrent concrètement pourquoi chaque bonne "
    "pratique existe : OAEP protège contre la malléabilité, RFC 6979 empêche la "
    "réutilisation catastrophique du nonce ECDSA, AES-GCM détecte les modifications "
    "que CBC laisse passer, HMAC_DRBG remplace le MT19937 prédictible."
)
add_para(
    "La menace quantique rend cette architecture vulnérable à moyen terme pour toutes "
    "les primitives à clé publique. Une migration vers des schémas post-quantiques hybrides "
    "(X25519 + ML-KEM, ECDSA + ML-DSA) est la voie recommandée."
)

doc.add_paragraph()
add_para(
    "Références : RFC 2104, RFC 4231, RFC 5869, RFC 6979, RFC 8017, RFC 3526, RFC 5280 ; "
    "FIPS 180-4, FIPS 197, FIPS 186-5 ; NIST SP 800-90A, NIST SP 800-22.",
    italic=True
)

# ════════════════════════════════════════════════════════════════════════════
# SAUVEGARDE
# ════════════════════════════════════════════════════════════════════════════
out = os.path.join(os.path.dirname(__file__), "rapport_cryptovault.docx")
doc.save(out)
print(f"Rapport genere : {out}")
