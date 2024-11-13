from numba import njit


@njit
def key_schedule(masterKey):
    """ Generate round keys for the PRESENT24 cipher from the master key.

    :param masterKey: PRESENT24 key (24-bit).
    :return: round_keys: list of the 11 PRESENT24 round keys.
    """
    SBOX = [0xc, 0x5, 0x6, 0xb,
            0x9, 0x0, 0xa, 0xd,
            0x3, 0xe, 0xf, 0x8,
            0x4, 0x7, 0x1, 0x2]

    # 80-bit key stored as a tuple of 40-bit halves because of numba
    # compilation being limited to 64-bit int.
    key = (masterKey << 16, 0x0000000000)
    roundKeys = [0x000000]

    for i in range(1, 11):
        temp = key[0] << 21
        firstHalf = (key[1] << 21 | key[0] >> 19) & 0xffffffffff
        secondHalf = (temp | key[1] >> 19) & 0xffffffffff
        key = (firstHalf, secondHalf)

        firstHalf = ((SBOX[key[0] >> 36]) << 36) | (key[0] & 0xfffffffff)
        secondHalf = key[1] ^ (i << 15)
        key = (firstHalf, secondHalf)
        roundKeys.append(key[1] >> 16)
    return roundKeys
