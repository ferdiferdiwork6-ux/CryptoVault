"""
CryptoVault — Interface web centralisée (Flask).
Lancement : python app/interface.py
Accès     : http://localhost:5000
"""
from __future__ import annotations
import os, sys, json, hashlib, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from flask import Flask, render_template, request, jsonify

app = Flask(__name__, template_folder="templates")
app.secret_key = os.urandom(24)

# ── État de session en mémoire (démonstration) ───────────────────────────────
from app.server import ServeurCryptoVault
from app.client import ClientCryptoVault
from app.vault  import CoffreFort

_serveur    = ServeurCryptoVault()
_clients    = {}   # username → ClientCryptoVault
_coffre     = CoffreFort()
_cles_rsa   = {}   # username → {publique, privee}

# ─────────────────────────────────────────────────────────────────────────────
# PAGE PRINCIPALE
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")

# ─────────────────────────────────────────────────────────────────────────────
# MODULE 1 — HACHAGE
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/hachage/empreinte", methods=["POST"])
def api_empreinte():
    texte = request.json.get("texte", "")
    data  = texte.encode()
    return jsonify({
        "MD5":     hashlib.md5(data).hexdigest(),
        "SHA-1":   hashlib.sha1(data).hexdigest(),
        "SHA-256": hashlib.sha256(data).hexdigest(),
        "SHA3-256":hashlib.sha3_256(data).hexdigest(),
    })

@app.route("/api/hachage/avalanche", methods=["POST"])
def api_avalanche():
    from cryptolib.hashing import effet_avalanche
    texte = request.json.get("texte", "Hello")
    res   = effet_avalanche(texte.encode()[:64])
    return jsonify({
        "pourcentage": round(res["pourcentage"], 1),
        "bits_sortie": res["bits_sortie"],
        "moyenne":     round(res["moyenne_bits_changes"], 1),
    })

@app.route("/api/hachage/hmac", methods=["POST"])
def api_hmac():
    from cryptolib.hashing import hmac_sha256
    cle     = request.json.get("cle", "secret").encode()
    message = request.json.get("message", "bonjour").encode()
    tag     = hmac_sha256(cle, message)
    return jsonify({"hmac_sha256": tag.hex()})

@app.route("/api/hachage/collision", methods=["POST"])
def api_collision():
    from cryptolib.hashing import attaque_anniversaire_32bits
    res = attaque_anniversaire_32bits()
    return jsonify(res)

@app.route("/api/hachage/mdp", methods=["POST"])
def api_mdp():
    from cryptolib.hashing import hacher_mot_de_passe, verifier_mot_de_passe
    mdp  = request.json.get("mdp", "motdepasse")
    stocke, duree = hacher_mot_de_passe(mdp, iterations=50_000)
    ok   = verifier_mot_de_passe(mdp, stocke)
    ok2  = verifier_mot_de_passe("mauvais", stocke)
    return jsonify({
        "stocke":   stocke[:80] + "...",
        "duree_ms": round(duree * 1000, 1),
        "verif_ok": ok,
        "mauvais_rejete": not ok2,
    })

# ─────────────────────────────────────────────────────────────────────────────
# MODULE 3 — RSA
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/rsa/generer", methods=["POST"])
def api_rsa_generer():
    from cryptolib.rsa import generer_cles_rsa
    debut = time.time()
    cles  = generer_cles_rsa(bits=512)
    duree = time.time() - debut
    return jsonify({
        "bits_module":   cles["bits_module"],
        "e":             cles["publique"]["e"],
        "n_bits":        cles["publique"]["n"].bit_length(),
        "duree_ms":      round(duree * 1000, 1),
    })

@app.route("/api/rsa/chiffrer", methods=["POST"])
def api_rsa_chiffrer():
    from cryptolib.rsa import generer_cles_rsa, chiffrer_rsa, dechiffrer_rsa
    message = request.json.get("message", "Bonjour").encode()
    cles    = generer_cles_rsa(bits=512)
    chiffre = chiffrer_rsa(message, cles["publique"])
    clair   = dechiffrer_rsa(chiffre, cles["privee"])
    return jsonify({
        "message_original": message.decode(),
        "chiffre_hex":      chiffre.hex()[:64] + "...",
        "dechiffre":        clair.decode(),
        "roundtrip_ok":     clair == message,
    })

@app.route("/api/rsa/attaque_malleable", methods=["POST"])
def api_rsa_malleabilite():
    from lab.attaques_rsa import attaque_malleabilite
    from cryptolib.numtheory import inverse_mod, expmod
    p, q, e = 61, 53, 17
    n   = p * q
    phi = (p-1)*(q-1)
    d   = inverse_mod(e, phi)
    M   = int(request.json.get("message", 42))
    C   = expmod(M, e, n)
    res = attaque_malleabilite(n, e, C)
    k   = res["facteur"]
    M_retrouve = expmod(res["C_modifie"], d, n) // k
    return jsonify({
        "M_original":  M,
        "C_original":  C,
        "C_modifie":   res["C_modifie"],
        "M_retrouve":  M_retrouve,
        "succes":      M_retrouve == M,
    })

# ─────────────────────────────────────────────────────────────────────────────
# MODULE 4 — DIFFIE-HELLMAN
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/dh/echange", methods=["POST"])
def api_dh_echange():
    from cryptolib.dh import simuler_echange_dh
    res = simuler_echange_dh("demo")
    return jsonify({
        "A":             res["A"],
        "B":             res["B"],
        "secret_commun": res["secret_commun"],
        "cle_enc":       res["cle_chiffrement"][:32] + "...",
        "groupe":        f"p=23, g=5 (demo)",
    })

@app.route("/api/dh/mitm", methods=["POST"])
def api_dh_mitm():
    from lab.attaques_dh import simuler_mitm
    from cryptolib.dh import GROUPES
    p, g = GROUPES["demo"]["p"], GROUPES["demo"]["g"]
    res  = simuler_mitm(p, g)
    return jsonify({
        "message_original":   res["message_original"].decode(),
        "message_lu_mallory": res["message_lu_mallory"].decode(),
        "mallory_a_lu":       res["mallory_a_lu"],
        "alice_detecte":      res["alice_detecte_mitm"],
    })

@app.route("/api/dh/bsgs", methods=["POST"])
def api_dh_bsgs():
    from lab.attaques_dh import attaque_bsgs_dh
    bits = int(request.json.get("bits", 25))
    bits = min(max(bits, 15), 30)
    res  = attaque_bsgs_dh(bits)
    return jsonify({
        "bits":     res["bits_premier"],
        "succes":   res["succes"],
        "duree_ms": res["duree_ms"],
        "sqrt_p":   res["complexite_theorique_sqrt"],
    })

# ─────────────────────────────────────────────────────────────────────────────
# MODULE 5 — ECC
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/ecc/ecdh", methods=["POST"])
def api_ecdh():
    from cryptolib.ecc import P256, ecdh_generer_cle, ecdh_secret_partage
    debut = time.time()
    d_a, Q_a = ecdh_generer_cle(P256)
    d_b, Q_b = ecdh_generer_cle(P256)
    K_a = ecdh_secret_partage(d_a, Q_b, P256)
    K_b = ecdh_secret_partage(d_b, Q_a, P256)
    duree = time.time() - debut
    return jsonify({
        "courbe":        "NIST P-256",
        "secret_commun": K_a == K_b,
        "secret_hex":    K_a.hex()[:32] + "...",
        "duree_ms":      round(duree * 1000, 1),
    })

@app.route("/api/ecc/ecdsa", methods=["POST"])
def api_ecdsa():
    from cryptolib.ecc import P256, ecdh_generer_cle, ecdsa_signer, ecdsa_verifier
    message = request.json.get("message", "Bonjour").encode()
    d, Q    = ecdh_generer_cle(P256)
    sig     = ecdsa_signer(message, d, P256)
    ok      = ecdsa_verifier(message, sig, Q, P256)
    ok2     = ecdsa_verifier(b"autre", sig, Q, P256)
    return jsonify({
        "message":         message.decode(),
        "r":               hex(sig[0])[:20] + "...",
        "s":               hex(sig[1])[:20] + "...",
        "signature_valide": ok,
        "message_modifie_rejete": not ok2,
    })

@app.route("/api/ecc/nonce_attack", methods=["POST"])
def api_nonce_attack():
    from lab.attaques_ecc import demo_attaque_nonce_reutilise
    res = demo_attaque_nonce_reutilise()
    return jsonify({
        "succes":    res["succes"],
        "duree_ms":  res["duree_ms"],
        "explication": res["explication"],
    })

# ─────────────────────────────────────────────────────────────────────────────
# MODULE 6 — SYMÉTRIQUE
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/sym/cesar", methods=["POST"])
def api_cesar():
    from cryptolib.symmetric import cesar_chiffrer, cesar_dechiffrer, cesar_casser
    texte   = request.json.get("texte", "BONJOUR")
    decalage = int(request.json.get("decalage", 3))
    chiffre = cesar_chiffrer(texte, decalage)
    d, clair = cesar_casser(chiffre)
    return jsonify({
        "original": texte,
        "chiffre":  chiffre,
        "decalage_trouve": d,
        "clair_casse": clair,
    })

@app.route("/api/sym/aes_gcm", methods=["POST"])
def api_aes_gcm():
    from cryptolib.symmetric import aes_gcm_chiffrer, aes_gcm_dechiffrer
    message = request.json.get("message", "Message confidentiel").encode()
    cle     = os.urandom(32)
    nonce   = os.urandom(12)
    chiffre, tag = aes_gcm_chiffrer(cle, nonce, message)
    clair        = aes_gcm_dechiffrer(cle, nonce, chiffre, tag)
    return jsonify({
        "message":    message.decode(),
        "chiffre":    chiffre.hex()[:32] + "...",
        "tag":        tag.hex(),
        "roundtrip":  clair == message,
    })

@app.route("/api/sym/ecb_demo", methods=["POST"])
def api_ecb_demo():
    from lab.attaques_sym import demo_ecb_motif
    res = demo_ecb_motif()
    return jsonify({
        "ecb_blocs_identiques": res["ecb_blocs_identiques"],
        "cbc_blocs_identiques": res["cbc_blocs_identiques"],
        "explication":          res["explication"],
    })

@app.route("/api/sym/bitflip", methods=["POST"])
def api_bitflip():
    from lab.attaques_sym import attaque_bit_flipping_cbc
    cle = os.urandom(16)
    iv  = os.urandom(16)
    res = attaque_bit_flipping_cbc(cle, iv)
    return jsonify({
        "admin_avant":    res["admin_avant"],
        "admin_apres":    res["admin_apres"],
        "attaque_reussie": res["attaque_reussie"],
    })

# ─────────────────────────────────────────────────────────────────────────────
# MODULE 8 — PRNG
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/prng/comparer", methods=["POST"])
def api_prng_comparer():
    from cryptolib.prng import LCG, MersenneTwister, HMAC_DRBG
    from cryptolib.prng import stat_monobit, stat_chi2_octets
    N = 10_000
    resultats = {}
    for nom, gen in [("LCG", LCG(12345)), ("MT19937", MersenneTwister(42)), ("HMAC_DRBG", HMAC_DRBG())]:
        data = gen.octets(N) if hasattr(gen, "octets") else gen.generer_octets(N)
        mb   = stat_monobit(data)
        chi  = stat_chi2_octets(data)
        resultats[nom] = {
            "monobit": mb["passe"],
            "chi2":    chi["passe"],
            "p_monobit": mb["p_valeur"],
        }
    return jsonify(resultats)

@app.route("/api/prng/attaque_mt", methods=["POST"])
def api_attaque_mt():
    from lab.attaques_prng import demo_attaque_mt
    res = demo_attaque_mt()
    return jsonify({
        "succes":      res["succes"],
        "nb_corrects": res["nb_corrects"],
        "total":       res["total"],
        "taux":        res["taux"],
    })

@app.route("/api/prng/attaque_lcg", methods=["POST"])
def api_attaque_lcg():
    from lab.attaques_prng import demo_attaque_lcg
    res = demo_attaque_lcg()
    return jsonify({
        "succes":     res["succes"],
        "a_correct":  res["a_correct"],
        "c_correct":  res["c_correct"],
        "a_trouve":   res.get("a_trouve"),
        "c_trouve":   res.get("c_trouve"),
    })

# ─────────────────────────────────────────────────────────────────────────────
# MODULE 9 — MESSAGERIE
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/messagerie/inscrire", methods=["POST"])
def api_inscrire():
    data     = request.json
    username = data.get("username", "alice")
    mdp      = data.get("mdp", "motdepasse")
    if username in _clients:
        return jsonify({"succes": False, "erreur": f"'{username}' déjà inscrit."})
    client = ClientCryptoVault(username)
    cert   = client.generer_identite(mdp, _serveur)
    _clients[username] = client
    return jsonify({
        "succes": True,
        "username": username,
        "cert_sujet": cert["sujet"],
        "cert_serie": cert["serie"],
    })

@app.route("/api/messagerie/handshake", methods=["POST"])
def api_handshake():
    username = request.json.get("username", "alice")
    if username not in _clients:
        return jsonify({"succes": False, "erreur": "Utilisateur non inscrit."})
    client = _clients[username]
    cles   = client.handshake(_serveur)
    return jsonify({
        "succes":    True,
        "username":  username,
        "cle_enc":   cles["cle_enc"].hex()[:32] + "...",
        "cle_auth":  cles["cle_auth"].hex()[:32] + "...",
        "pfs":       True,
    })

@app.route("/api/messagerie/envoyer", methods=["POST"])
def api_envoyer():
    data     = request.json
    username = data.get("username", "alice")
    message  = data.get("message", "Bonjour !").encode()
    if username not in _clients:
        return jsonify({"succes": False, "erreur": "Utilisateur non inscrit."})
    client = _clients[username]
    if not hasattr(client, "_cle_enc"):
        client.handshake(_serveur)
    paquet = client.envoyer(message, _serveur)
    clair  = client.recevoir(paquet, _serveur)
    return jsonify({
        "succes":       True,
        "message":      message.decode(),
        "chiffre":      paquet["chiffre"][:32] + "...",
        "seq":          paquet["seq"],
        "roundtrip_ok": clair == message,
    })

# ─────────────────────────────────────────────────────────────────────────────
# MODULE 9 — COFFRE-FORT
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/vault/add", methods=["POST"])
def api_vault_add():
    from cryptolib.rsa import generer_cles_rsa
    from cryptolib.ecc import P256, ecdh_generer_cle
    data     = request.json
    nom      = data.get("nom", "fichier.txt")
    contenu  = data.get("contenu", "Contenu confidentiel").encode()
    username = data.get("username", "user1")
    if username not in _cles_rsa:
        _cles_rsa[username] = generer_cles_rsa(bits=512)
    if username + "_ecc" not in _cles_rsa:
        d, Q = ecdh_generer_cle(P256)
        _cles_rsa[username + "_ecc"] = {"d": d, "Q": Q}
    cles_rsa = _cles_rsa[username]
    ecc      = _cles_rsa[username + "_ecc"]
    racine   = _coffre.ajouter(nom, contenu, ecc["d"], [cles_rsa["publique"]])
    return jsonify({"succes": True, "nom": nom, "merkle_racine": racine[:32] + "..."})

@app.route("/api/vault/list", methods=["GET"])
def api_vault_list():
    return jsonify({"fichiers": _coffre.lister()})

@app.route("/api/vault/get", methods=["POST"])
def api_vault_get():
    data     = request.json
    nom      = data.get("nom", "fichier.txt")
    username = data.get("username", "user1")
    if username not in _cles_rsa or nom not in _coffre.lister():
        return jsonify({"succes": False, "erreur": "Fichier ou clé introuvable."})
    cles_rsa = _cles_rsa[username]
    ecc      = _cles_rsa[username + "_ecc"]
    contenu  = _coffre.obtenir(nom, cles_rsa["privee"], ecc["Q"])
    return jsonify({"succes": True, "nom": nom, "contenu": contenu.decode(errors="replace")})

# ─────────────────────────────────────────────────────────────────────────────
# BONUS — SHAMIR
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/shamir/partager", methods=["POST"])
def api_shamir():
    from cryptolib.shamir import partager_cle_bytes, reconstruire_cle_bytes
    data = request.json
    k    = int(data.get("k", 3))
    n    = int(data.get("n", 5))
    k    = max(2, min(k, 10))
    n    = max(k, min(n, 10))
    cle  = os.urandom(16)
    parts = partager_cle_bytes(cle, k, n)
    # Reconstruction avec les k premières parts
    recup = reconstruire_cle_bytes(parts[:k], 16)
    return jsonify({
        "cle_originale":   cle.hex(),
        "k": k, "n": n,
        "nb_parts":        len(parts),
        "parts_exemple":   [(xi, hex(yi)[:20]+"...") for xi, yi in parts[:3]],
        "cle_reconstruite": recup.hex(),
        "succes":          cle == recup,
    })

# ─────────────────────────────────────────────────────────────────────────────
# BONUS — ML-KEM vs ECDH
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/mlkem/comparer", methods=["POST"])
def api_mlkem():
    from cryptolib.mlkem import comparer_ecdh_mlkem
    res = comparer_ecdh_mlkem(n_essais=3)
    return jsonify(res)

@app.route("/api/mlkem/hybride", methods=["POST"])
def api_mlkem_hybride():
    from cryptolib.mlkem import echange_hybride_x25519_mlkem
    res = echange_hybride_x25519_mlkem()
    return jsonify(res)

# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("CryptoVault Interface — http://localhost:5000")
    app.run(debug=False, port=5000)
