SBOX = [
    0xc, 0x5, 0x6, 0xb,
    0x9, 0x0, 0xa, 0xd,
    0x3, 0xe, 0xf, 0x8,
    0x4, 0x7, 0x1, 0x2,
]


def key_scheduler(master_key):
    """ Algorithme de cadencement de clé.

    - Ajoute un padding pour avoir une clé de 80 bits pour garder
        l'algorithme de cadencement originel.
    - Pivote de 61 positions la clé de 80 bits vers la gauche.
    - Ensuite applique la boite de Subsitution sur les 4 bits de poids fort.
    - XOR les bits 15 à 19 de la clé par le numéro du tour i.
    - Il applique 11 fois les étapes précedentes pour avoir les 11 sous-clés.
    :param master_key: clé maitre de 24 bits.
    :return: round_keys: liste des 11 sous-clés.
    """
    key = master_key << 56
    round_keys = [0x000000]
    xor_step = 0b1 << 15

    while xor_step != 0x58000:
        key = bit_rotation(key)
        # 19 0xf pour séparer les 76 bits de poids faible
        key = ((SBOX[key >> 76]) << 76) | (key & 0xfffffffffffffffffff)
        key = key ^ xor_step
        xor_step += 0b1 << 15
        round_keys.append(((key >> 16) & 0xffffff))
    return round_keys


def bit_rotation(key):
    """ Pivote une clé de 61 positions vers la gauche.

    :param key: clé de 80 bits.
    :return: rotated: clé de 80 bits.
    """
    # 0x7ffff permet de garder les 19 bits de poids faible
    rotated = key & 0x7ffff
    rotated = (rotated << 61) | key >> 19
    return rotated
