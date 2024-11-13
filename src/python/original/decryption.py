""" Déchiffrement de PRESENT24
"""

from src.python.original.key_schedule import key_scheduler

# Initialisation des tables de Substitution et Permutation
SBOX = [
    0x5, 0xe, 0xf, 0x8,
    0xc, 0x1, 0x2, 0xd,
    0xb, 0x4, 0x6, 0x3,
    0x0, 0x7, 0x9, 0xa,
]
PBOX = [
    0, 4, 8, 12, 16, 20,
    1, 5, 9, 13, 17, 21,
    2, 6, 10, 14, 18, 22,
    3, 7, 11, 15, 19, 23,
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

    Pour le bit à la position i, P(i) = i * 4 mod 23.
    :param msg: message clair de 24 bits.
    :return: c: message chiffré par permutation.
    """
    c = 0x0
    for position in range(len(PBOX)-1):
        c |= ((msg >> position) & 0x1) << ((4*position) % 23)
    c |= msg & 0x800000
    return c


def decryption(master_key, c):
    """ Déchiffrement d'un chiffré c avec la clé c par PRESENT24.

    :param master_key: clé de 24 bits.
    :param c: message chiffré par PRESENT24 a déchiffrer.
    :return: m: message dechiffré par PRESENT24.
    """
    round_keys = key_scheduler(master_key)
    m = c ^ round_keys[-1]
    for key in range(len(round_keys) - 2, -1, -1):
        m = permutation(m)
        m = substitution(m)
        m = m ^ round_keys[key]
    return m


def decryption_with_round_keys(round_keys, c):
    """ Déchiffrement d'un message par PRESENT24 à partir des clés cadencées.

    :param round_keys: liste des 11 sous-clés.
    :param c: message chiffré de 24 bits.
    :return: m: message dechiffré par PRESENT24.
    """
    m = c ^ round_keys[-1]
    for key in range(len(round_keys) - 2, -1, -1):
        m = permutation(m)
        m = substitution(m)
        m = m ^ round_keys[key]
    return m


def doublepresent24(key1, key2, c):
    """ Déhiffrement d'un chiffré par 2-PRESENT24 à
        partir d'une clé secrète (key1, key2).

    :param mk1: première clé de chiffrement de 24 bits.
    :param mk2: deuxième clé de chiffrement de 24 bits.
    :param c: message chiffré de 24 bits.
    :return: m: message dechiffré par 2-PRESENT24 avec la clé (key1, key2).
    """
    c = decryption(key2, c)
    m = decryption(key1, c)
    return m


def affichage(m, c, master_key):
    if isinstance(master_key, tuple):
        print("Le message chiffré {:#08x} a été déchiffré en {:#08x}"
              "à l'aide de la clé ({:#08x}, {:#08x}).".format(
               c, m, master_key[0], master_key[1]))
    else:
        print("Le message chiffré {:#08x} a été déchiffré en {:#08x}"
              "à l'aide de la clé {:#08x}.".format(
               c, m, master_key))


def test():
    master_key = 0xd1bd2d
    msg = 0x47a929
    decrypted = decryption(master_key, msg)
    print("Ox{:x}".format(decrypted))
