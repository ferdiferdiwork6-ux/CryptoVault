"""
Attaques pédagogiques sur les générateurs pseudo-aléatoires (module 8).
- Attaque 1 : retrouver (a, c) d'un LCG depuis 3 sorties consécutives
- Attaque 2 : reconstituer l'état du Mersenne Twister (624 sorties)
              et prédire les sorties suivantes
"""
from __future__ import annotations
from cryptolib.prng import LCG, MersenneTwister


# ---------------------------------------------------------------------------
# Attaque 1 : Casser un LCG
# Avec x0, x1 = a*x0+c, x2 = a*x1+c :
#   x1 - x2 = a*(x0 - x1)  (mod m)
#   → a = (x1 - x2) * inverse(x0 - x1)  mod m  (si m connu)
#   → c = x1 - a*x0  mod m
# ---------------------------------------------------------------------------

def _pgcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return a

def _inverse_mod(a: int, m: int) -> int | None:
    """Inverse modulaire si existe, sinon None."""
    g, x, _ = _egcd(a % m, m)
    return x % m if g == 1 else None

def _egcd(a: int, b: int):
    if b == 0:
        return a, 1, 0
    g, x, y = _egcd(b, a % b)
    return g, y, x - (a // b) * y


def attaque_lcg(m: int, sorties: list[int]) -> dict:
    """
    Retrouve (a, c) d'un LCG connaissant m et 3 sorties consécutives.
    x_{n+1} - x_{n+2} = a * (x_n - x_{n+1})  mod m
    """
    if len(sorties) < 3:
        return {"succes": False, "raison": "Besoin d'au moins 3 sorties"}

    x0, x1, x2 = sorties[0], sorties[1], sorties[2]
    diff0 = (x0 - x1) % m
    diff1 = (x1 - x2) % m

    inv = _inverse_mod(diff0, m)
    if inv is None:
        return {"succes": False, "raison": f"pgcd({diff0}, {m}) != 1"}

    a_trouve = (diff1 * inv) % m
    c_trouve = (x1 - a_trouve * x0) % m

    # Vérification sur les sorties connues
    etat = x0
    correct = True
    for attendu in sorties[1:]:
        etat = (a_trouve * etat + c_trouve) % m
        if etat != attendu:
            correct = False
            break

    return {
        "succes":    correct,
        "a_trouve":  a_trouve,
        "c_trouve":  c_trouve,
        "m":         m,
    }


def demo_attaque_lcg() -> dict:
    """Génère un LCG secret et le casse avec 3 sorties."""
    import os
    # Paramètres "secrets"
    m = 2**32
    a = 1664525
    c = 1013904223
    graine = int.from_bytes(os.urandom(4), "big")
    lcg = LCG(graine, m=m, a=a, c=c)
    sorties = lcg.generer(5)   # observer 5 sorties consécutives

    res = attaque_lcg(m, sorties)
    res["a_reel"] = a
    res["c_reel"] = c
    res["a_correct"] = res.get("a_trouve") == a
    res["c_correct"] = res.get("c_trouve") == c
    return res


# ---------------------------------------------------------------------------
# Attaque 2 : Reconstituer l'état du Mersenne Twister
# L'opération de "tempering" est inversible. En observant 624 sorties,
# on reconstruit mt[] et on peut prédire toutes les sorties suivantes.
# ---------------------------------------------------------------------------

def _inverser_tempering(y: int) -> int:
    """Inverse la transformation de tempering du MT19937."""
    # Inverser y ^= y >> 18
    y ^= y >> 18

    # Inverser y ^= (y << 15) & 0xEFC60000
    y ^= (y << 15) & 0xEFC60000

    # Inverser y ^= (y << 7) & 0x9D2C5680  (par blocs de 7 bits)
    tmp = y
    for _ in range(4):
        tmp = y ^ ((tmp << 7) & 0x9D2C5680)
    y = tmp

    # Inverser y ^= y >> 11  (par blocs de 11 bits)
    tmp = y
    for _ in range(3):
        tmp = y ^ (tmp >> 11)
    y = tmp

    return y & 0xFFFFFFFF


def attaque_mt19937(sorties_observees: list[int]) -> dict:
    """
    Reconstitue l'état interne du MT19937 à partir de 624 sorties consécutives.
    Retourne le nombre de prédictions correctes sur les 20 sorties suivantes.
    """
    if len(sorties_observees) < 624:
        return {"succes": False, "raison": "Besoin d'au moins 624 sorties"}

    # Reconstituer mt[]
    mt_reconstruit = [_inverser_tempering(v) for v in sorties_observees[:624]]

    # Créer un MT avec cet état reconstitué
    mt_clone = MersenneTwister(0)
    mt_clone.mt    = mt_reconstruit[:]
    mt_clone.index = 624   # forcer la régénération au prochain appel

    return {"mt_clone": mt_clone, "succes": True}


def demo_attaque_mt() -> dict:
    """Observe 624 sorties du MT, clone l'état, prédit les suivantes."""
    mt_original = MersenneTwister(42)
    observees   = [mt_original.suivant_u32() for _ in range(624)]

    res = attaque_mt19937(observees)
    if not res["succes"]:
        return res

    mt_clone = res["mt_clone"]

    # Prédire les 20 prochaines sorties
    N_PRED = 20
    predictions  = [mt_clone.suivant_u32()   for _ in range(N_PRED)]
    valeurs_reel = [mt_original.suivant_u32() for _ in range(N_PRED)]

    nb_corrects = sum(p == r for p, r in zip(predictions, valeurs_reel))
    return {
        "succes":               True,
        "predictions":          predictions,
        "valeurs_reelles":      valeurs_reel,
        "nb_corrects":          nb_corrects,
        "total":                N_PRED,
        "taux":                 nb_corrects / N_PRED,
        "explication": (
            "Le tempering du MT est bijectif donc inversible. "
            "624 sorties suffisent à reconstituer mt[] en entier. "
            "Ensuite, le générateur est totalement prévisible. "
            "C'est pourquoi on ne doit JAMAIS utiliser MT pour la cryptographie."
        ),
    }


if __name__ == "__main__":
    print("=" * 60)
    print("ATTAQUE 1 : Casser un LCG (a, c connus via 3 sorties)")
    print("=" * 60)
    res = demo_attaque_lcg()
    print(f"  Succès     : {res['succes']}")
    print(f"  a trouvé   : {res.get('a_trouve')}  (réel : {res['a_reel']})")
    print(f"  c trouvé   : {res.get('c_trouve')}  (réel : {res['c_reel']})")
    print(f"  a correct  : {res['a_correct']}")
    print(f"  c correct  : {res['c_correct']}")
    print()

    print("=" * 60)
    print("ATTAQUE 2 : Cloner l'état du Mersenne Twister (624 sorties)")
    print("=" * 60)
    res2 = demo_attaque_mt()
    print(f"  Prédictions correctes : {res2['nb_corrects']}/{res2['total']}")
    print(f"  Taux                  : {res2['taux']*100:.0f}%")
    print(f"  {res2['explication']}")
