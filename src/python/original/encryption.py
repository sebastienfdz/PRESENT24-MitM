""" Chiffrement par bloc PRESENT24
"""

from src.python.original.key_schedule import key_scheduler

# Initialisation des tables de Substitution et Permutation
SBOX = [
    0xc, 0x5, 0x6, 0xb,
    0x9, 0x0, 0xa, 0xd,
    0x3, 0xe, 0xf, 0x8,
    0x4, 0x7, 0x1, 0x2,
]
PBOX = [
    0, 6, 12, 18, 1, 7,
    13, 19, 2, 8, 14, 20,
    3, 9, 15, 21, 4, 10,
    16, 22, 5, 11, 17, 23,
]


def substitution(msg):
    """ Substitution d'entier de 24 bits.

    :param msg: message clair de 24 bits.
    :return: c: message chiffré par substitution.
    """
    c = 0x0
    for word_nb in range(6):
        c |= SBOX[(msg >> word_nb*4) & 0xf] << word_nb*4
    return c


def permutation(msg):
    """ Permutation d'entier de 24 bits.

    Pour le bit à la position i, P(i) = i * 6 mod 23.
    :param msg: message clair de 24 bits.
    :return: c: message chiffré par permutation.
    """
    c = 0x0
    for position in range(len(PBOX)-1):
        c |= ((msg >> position) & 0x1) << ((6*position) % 23)
    c |= msg & 0x800000
    return c


def encryption(master_key, m):
    """ Chiffrement PRESENT24 d'un message clair m avec une clé de 24 bit.

    :param master_key: clé de 24 bits.
    :param m: message clair de 24 bits.
    :return: c: message chiffré par PRESENT24.
    """
    round_keys = key_scheduler(master_key)
    c = m
    for key in round_keys[:-1]:
        c = c ^ key
        c = substitution(c)
        c = permutation(c)
    c = c ^ round_keys[-1]
    return c


def encryption_with_round_keys(round_keys, m):
    """ Chiffrement PRESENT24 d'un message clair m à partir des clés cadencées.

    :param round_keys: liste des 11 sous-clés.
    :param m: message clair de 24 bits.
    :return: c: message chiffré par PRESENT24.
    """
    c = m
    for key in round_keys[:-1]:
        c = c ^ key
        c = substitution(c)
        c = permutation(c)
    c = c ^ round_keys[-1]
    return c


def doublepresent24(key1, key2, m):
    """ Chiffrement 2-PRESENT24 d'un message clair m avec la clé (key1, key2).

    :param key1: première clé de chiffrement de 24 bits.
    :param key2: deuxième clé de chiffrement de 24 bits.
    :param m: message clair de 24 bits.
    :return: c: message chiffré par 2PRESENT24 avec la clé (key1, key2).
    """
    c = encryption(key1, m)
    c = encryption(key2, c)
    return c


def affichage(m, c, master_key):
    if isinstance(master_key, tuple):
        print("Le message clair {:#08x} a été chiffré en {:#08x} à l'aide de "
              "la clé ({:#08x}, {:#08x}).".format(
                m, c, master_key[0], master_key[1]))
    else:
        print("Le message clair {:#08x} a été chiffré en {:#08x} à l'aide de"
              "la clé {:#08x}.".format(m, c, master_key))


def test():
    master_key = 0xd1bd2d
    msg = 0xf955b9
    encrypted = encryption(master_key, msg)
    print("Ox{:x}".format(encrypted))
