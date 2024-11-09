""" Attaque par le mileu à l'aide de deux couples clair-chiffré
(m1, c1) = (0xd41330, 0x2f4a58)
(m2, c2) = (0x9d0af2, 0x57c9d6)
Couple de clés (k1, k2) retrouvés (3d93b5, 3aa01a)

- Pour chaque clé de 24 bits, on chiffre m1 et déchiffre c1 pour mettre les
    résultats dans 2 listes respectivement dans Lm et Lc.
- On trie Lm et Lc.
- On compare les messages obtenus dans Lm et Lc, les listes étant triées la
    complexité est de l'ordre de n + m
    (avec n et m le nombre d'élément de Lm et Lc).
- Si il y a des couples de valeurs de Lm et Lc égales alors on essaye de
    savoir si le couple de clés est le bon.
- Pour cela on regarde si c2 = PRESENT24(k1, PRESENT24(k2, m2))
- Si c'est le cas alors la clé (k1, k2) est une clé candidate pour être la
    clé secrète recherchée
"""

from src.original.encryption import encryption_with_round_keys, doublepresent24
from src.original.decryption import decryption_with_round_keys
from src.original.key_schedule import key_scheduler

K = 2**24


def lists_generation(m, c=0):
    """
    Génère les listes Lc et Lm de tuples (chiffré(m), clé).
    Pour chaque clé on chiffre m1 et déchiffre c1.

    :param m: Message clair du couple clair-chiffré choisi.
    :param c: Message chiffré du couple clair-chiffré choisi.
    :return: list_m: liste Lm contenant K tuples (chiffré(m), clé).
             list_c: liste Lc contenant K tuples (déchiffré(c), clé).
    """
    list_m = []
    list_c = []
    for master_key in range(K):
        round_keys = key_scheduler(master_key)
        encrypted = (encryption_with_round_keys(round_keys, m), master_key)
        decrypted = (decryption_with_round_keys(round_keys, c), master_key)
        list_m.append(encrypted)
        list_c.append(decrypted)
    return list_m, list_c


def search(list_m, list_c, m, c):
    """
    On cherche des couples de valeurs égales dans list_m et list_c.
    Ces collisions nous permettent de chercher le
        couples de clés (k1, k2) utilisé pour le chiffrement.

    :param list_m: liste Lm contenant K tuples (chiffré(m), clé).
    :param list_c: liste Lc contenant K tuples (déchiffré(c), clé).
    :param m: message clair
    :param c: message chiffré
    :return: collision: liste des couples de clés candidats (k1, k2)
    """
    i, j = 0, 0
    collision = []
    while i < len(list_m) and j < len(list_c):
        encrypted = list_m[i][0]
        decrypted = list_c[j][0]
        if encrypted < decrypted:
            i += 1
        elif encrypted > decrypted:
            j += 1
        else:
            doublepresent = doublepresent24(list_m[i][1], list_c[j][1], m)
            if doublepresent == c:
                collision.append((list_m[i][1], list_c[j][1]))
            i += 1
            j += 1
    return collision


def attack_2present24(m1, c1, m2, c2):
    list_m_, list_c_ = lists_generation(m1, c1)
    list_m_.sort()
    list_c_.sort()
    common_keys = search(list_m_, list_c_, m2, c2)
    affichage(m1, c1, m2, c2, common_keys)


def affichage(m1, c1, m2, c2, common_keys):
    print("Les couples clair-chiffré utilisés pour l'attaque sont "
          "({:#08x}, {:#08x}) et ({:#08x}, {:#08x})".format(m1, c1, m2, c2))
    if not common_keys:
        print("Aucun couple de clé n'a été retrouvés par attaque par"
              "le milieu avec ces couples clair-chiffré")
        quit()
    print("Les couples de clés retrouvés par l'attaque sont les suivantes :")
    for key1, key2 in common_keys:
        print("({:#08x}, {:#08x})".format(key1, key2))


def test():
    m1, c1 = 0xd41330, 0x2f4a58
    m2, c2 = 0x9d0af2, 0x57c9d6
    res = attack_2present24(m1, c1, m2, c2)
    print("Ox{:x}".format(res))
