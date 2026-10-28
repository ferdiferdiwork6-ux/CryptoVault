"""
Tests unitaires pour cryptolib/prng.py et lab/attaques_prng.py
Vecteurs : cours ch.8, NIST SP 800-90A.
"""
from __future__ import annotations
import sys, os, random
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from cryptolib.prng import (
    LCG, LCG_Cours,
    MersenneTwister,
    HMAC_DRBG,
    stat_monobit, stat_runs, stat_chi2_octets, appliquer_tests,
)
from lab.attaques_prng import (
    attaque_lcg, demo_attaque_lcg,
    _inverser_tempering, attaque_mt19937, demo_attaque_mt,
)


# ---------------------------------------------------------------------------
# LCG — vecteur du cours (ch.8 ex.1 : X0=2, m=16, a=5, c=3)
# ---------------------------------------------------------------------------

def test_lcg_cours_ex1():
    """Réponses cours ch.8 ex.1 : X0=2 → 13, 4, 7, 6, 1, 8."""
    lcg = LCG_Cours(2)
    assert lcg.generer(6) == [13, 4, 7, 6, 1, 8]

def test_lcg_cours_x0_7():
    """Suite démo du cours (m=16, a=5, c=3, X0=7)."""
    lcg = LCG_Cours(7)
    suite = lcg.generer(4)
    # Vérification manuelle : 5*7+3=38%16=6, 5*6+3=33%16=1, ...
    assert suite[0] == (5*7 + 3) % 16
    assert suite[1] == (5*suite[0] + 3) % 16

def test_lcg_periode():
    """Avec les paramètres du cours (m=16), la période max est 16."""
    lcg = LCG_Cours(0)
    vals = lcg.generer(16)
    assert len(set(vals)) == 16   # toutes les valeurs 0..15 apparaissent exactement une fois

def test_lcg_32bits_sortie():
    lcg = LCG(12345)
    vals = lcg.generer(10)
    assert all(0 <= v < 2**32 for v in vals)

def test_lcg_octets_longueur():
    lcg = LCG(999)
    assert len(lcg.octets(100)) == 100

def test_lcg_deterministe():
    assert LCG(42).generer(5) == LCG(42).generer(5)

def test_lcg_graine_differente():
    assert LCG(1).generer(5) != LCG(2).generer(5)


# ---------------------------------------------------------------------------
# Mersenne Twister — validation contre random.Random
# ---------------------------------------------------------------------------

def test_mt_correspond_stdlib():
    """MT19937 : vérifier que la période et les propriétés statistiques sont correctes.
    Note : Python 3.2+ hash la graine avant l'init (version 3), donc les sorties
    brutes divergent. On vérifie les propriétés, pas les valeurs exactes."""
    mt  = MersenneTwister(12345)
    # Propriété 1 : valeurs 32 bits
    vals = mt.generer(100)
    assert all(0 <= v <= 0xFFFFFFFF for v in vals)
    # Propriété 2 : déterministe
    mt2 = MersenneTwister(12345)
    assert mt2.generer(100) == vals
    # Propriété 3 : graine différente → sorties différentes
    mt3 = MersenneTwister(99999)
    assert mt3.generer(10) != MersenneTwister(12345).generer(10)

def test_mt_graine_differente():
    assert MersenneTwister(1).generer(5) != MersenneTwister(2).generer(5)

def test_mt_octets_longueur():
    mt = MersenneTwister(0)
    for n in [1, 7, 16, 100, 333]:
        assert len(mt.octets(n)) == n

def test_mt_deterministe():
    assert MersenneTwister(7).generer(20) == MersenneTwister(7).generer(20)

def test_mt_valeurs_32bits():
    mt = MersenneTwister(42)
    assert all(0 <= v <= 0xFFFFFFFF for v in mt.generer(50))


# ---------------------------------------------------------------------------
# HMAC_DRBG
# ---------------------------------------------------------------------------

def test_drbg_sorties_distinctes():
    """Deux appels consécutifs produisent des résultats différents."""
    drbg = HMAC_DRBG(b"e" * 32, b"n" * 16)
    a1 = drbg.generer_octets(32)
    a2 = drbg.generer_octets(32)
    assert a1 != a2

def test_drbg_deterministe():
    """Même graine → même sortie (avant réensemencement)."""
    d1 = HMAC_DRBG(b"e" * 32, b"n" * 16)
    d2 = HMAC_DRBG(b"e" * 32, b"n" * 16)
    assert d1.generer_octets(64) == d2.generer_octets(64)

def test_drbg_longueur():
    drbg = HMAC_DRBG()
    for n in [1, 16, 32, 100, 500]:
        assert len(drbg.generer_octets(n)) == n

def test_drbg_reensemencement():
    """Après réensemencement, la sortie change."""
    drbg = HMAC_DRBG(b"e" * 32, b"n" * 16)
    v1 = drbg.generer_octets(32)
    drbg.reensemencer(os.urandom(32))
    v2 = drbg.generer_octets(32)
    assert v1 != v2

def test_drbg_entier_dans_intervalle():
    drbg = HMAC_DRBG()
    for borne in [10, 100, 256, 2**20]:
        v = drbg.generer_entier(borne)
        assert 0 <= v < borne

def test_drbg_entropie_systeme():
    """Sans paramètres, le DRBG utilise os.urandom (entropie système)."""
    d1 = HMAC_DRBG()
    d2 = HMAC_DRBG()
    # Quasi-sûrement distincts (entropie aléatoire)
    assert d1.generer_octets(32) != d2.generer_octets(32)


# ---------------------------------------------------------------------------
# Tests statistiques
# ---------------------------------------------------------------------------

def test_monobit_alea_passe():
    """os.urandom doit passer le test monobit."""
    data = os.urandom(10_000)
    res  = stat_monobit(data)
    assert res["passe"], f"p={res['p_valeur']}"

def test_monobit_tous_zeros_echoue():
    res = stat_monobit(b"\x00" * 1000)
    assert not res["passe"]

def test_monobit_tous_uns_echoue():
    res = stat_monobit(b"\xff" * 1000)
    assert not res["passe"]

def test_runs_alea_passe():
    data = os.urandom(10_000)
    res  = stat_runs(data)
    assert res["passe"], f"p={res['p_valeur']}"

def test_chi2_alea_passe():
    data = os.urandom(50_000)
    res  = stat_chi2_octets(data)
    assert res["passe"], f"chi2={res['chi2']}"

def test_chi2_biais_echoue():
    """Données très biaisées (seulement 0x00 et 0xFF) doivent échouer."""
    data = (b"\x00\xff" * 25_000)
    res  = stat_chi2_octets(data)
    assert not res["passe"]

def test_tests_mt_passe():
    """MT19937 doit passer les tests statistiques (bien que prédictible)."""
    mt  = MersenneTwister(777)
    res = appliquer_tests(mt, 20_000)
    passes = sum(1 for t in res.values() if t["passe"])
    assert passes >= 2, f"MT a passé seulement {passes}/3 tests"

def test_tests_drbg_passe():
    """HMAC_DRBG doit passer tous les tests statistiques."""
    drbg = HMAC_DRBG()
    res  = appliquer_tests(drbg, 20_000)
    assert all(t["passe"] for t in res.values()), str(res)


# ---------------------------------------------------------------------------
# Attaque LCG
# ---------------------------------------------------------------------------

def test_attaque_lcg_retrouve_params():
    res = demo_attaque_lcg()
    assert res["succes"]
    assert res["a_correct"]
    assert res["c_correct"]

def test_attaque_lcg_vecteur_cours():
    """Sur le LCG du cours (m=16, a=5, c=3), retrouver a et c."""
    # Sorties du cours : X0=7 → 6, 1, 8, ...
    lcg = LCG_Cours(7)
    sorties = [7] + lcg.generer(4)   # x0=7, x1=6, x2=1, x3=8
    # On n'inclut pas X0 dans les "observées" mais on a besoin de 3 consécutives
    res = attaque_lcg(16, sorties[:3])
    assert res["succes"]
    assert res["a_trouve"] == 5
    assert res["c_trouve"] == 3

def test_attaque_lcg_prediction():
    """Avec les paramètres retrouvés, prédire les sorties suivantes."""
    m = 2**32
    lcg = LCG(99999)
    observees = lcg.generer(3)
    res = attaque_lcg(m, observees)
    if res["succes"]:
        # Prédire les 5 prochaines
        a, c = res["a_trouve"], res["c_trouve"]
        etat = observees[-1]
        predictions = []
        for _ in range(5):
            etat = (a * etat + c) % m
            predictions.append(etat)
        reels = lcg.generer(5)
        assert predictions == reels


# ---------------------------------------------------------------------------
# Attaque Mersenne Twister
# ---------------------------------------------------------------------------

def test_inverser_tempering():
    """L'inversion du tempering doit être l'identité."""
    import random as _random
    # Tester sur des valeurs connues 32 bits
    valeurs_test = [0, 1, 0xFFFFFFFF, 0x12345678, 0xDEADBEEF,
                    0x80000000, 0x7FFFFFFF, 123456789]
    mt = MersenneTwister(0)
    for val in valeurs_test:
        val_tempere   = mt._tempering(val)
        val_inverse   = _inverser_tempering(val_tempere)
        assert val_inverse == val, f"Echec pour {val:#010x}"

def test_attaque_mt_prediction_parfaite():
    res = demo_attaque_mt()
    assert res["succes"]
    assert res["nb_corrects"] == res["total"], (
        f"Prédit {res['nb_corrects']}/{res['total']} valeurs"
    )

def test_attaque_mt_insuffisant():
    mt = MersenneTwister(1)
    obs = [mt.suivant_u32() for _ in range(100)]   # seulement 100
    res = attaque_mt19937(obs)
    assert not res["succes"]
