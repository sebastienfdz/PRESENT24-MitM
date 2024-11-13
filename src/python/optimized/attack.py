from numba import njit
from time import process_time

from src.optimized.key_schedule import key_schedule

K = 1 << 24


@njit
def encrypt(roundKeys, plain):
    """ PRESENT24 encryption of a plaintext with a 24-bit key.

    :param master_key: 24-bit key.
    :param plain: 24-bit plaintext.
    :return: cypher: PRESENT24 24-bit cypher.
    """
    SBOX = [0xc, 0x5, 0x6, 0xb,
            0x9, 0x0, 0xa, 0xd,
            0x3, 0xe, 0xf, 0x8,
            0x4, 0x7, 0x1, 0x2]
    cypher = plain
    for key in range(10):
        cypher = cypher ^ roundKeys[key]
        # Substitution
        tmp = 0x0
        for bitBloc in range(6):
            tmp |= SBOX[(cypher >> bitBloc * 4) & 0xf] << bitBloc * 4
        cypher = tmp
        # Permutation
        tmp = 0x0
        for bit in range(23):
            tmp |= ((cypher >> bit) & 0x1) << ((6 * bit) % 23)
        cypher = tmp | cypher & 0x800000

    cypher = cypher ^ roundKeys[-1]
    return cypher


@njit
def double_present24(key1, key2, plain):
    """ 2-PRESENT24 encryption of a plaintext with a 48-bit key (k1, k2). """
    return encrypt(key_schedule(key2), encrypt(key_schedule(key1), plain))


@njit
def decrypt(roundKeys, cypher):
    """ PRESENT24 decryption of a cypher with a 24-bit key.

    :param master_key: 24-bit key.
    :param cypher: PRESENT24 24-bit cypher.
    :return: plain: 24-bit decrypted plaintext.
    """
    SBOX = [0x5, 0xe, 0xf, 0x8,
            0xc, 0x1, 0x2, 0xd,
            0xb, 0x4, 0x6, 0x3,
            0x0, 0x7, 0x9, 0xa]
    plain = cypher ^ roundKeys[-1]

    for key in range(9, -1, -1):
        # Permutation
        tmp = 0x0
        for bit in range(23):
            tmp |= ((plain >> bit) & 0x1) << ((4 * bit) % 23)
        plain = tmp | plain & 0x800000
        # Substitution
        tmp = 0x0
        for bitBloc in range(6):
            tmp |= SBOX[(plain >> bitBloc * 4) & 0xf] << bitBloc * 4
        plain = tmp ^ roundKeys[key]
    return plain


@njit
def generate_intermediate_states(plain, cypher):
    """ Generate intermediate encryption and decryption lists for the MitM attack. """
    plainIntermediate, cypherIntermediate = [(0, 0)] * K, [(0, 0)] * K
    for masterKey in range(K):
        roundKeys = key_schedule(masterKey)
        plainIntermediate[masterKey] = (encrypt(roundKeys, plain), masterKey)
        cypherIntermediate[masterKey] = (decrypt(roundKeys, cypher), masterKey)
    return plainIntermediate, cypherIntermediate


@njit
def search_candidates(plainIntermediates, cypherIntermediates, plain, cypher):
    """ Find matching keys between two sorted lists of tuples.

    :return: candidateKeys: list of tuples of candidate keys (key1, key2).
    """
    plainCount, cypherCount = len(plainIntermediates), len(cypherIntermediates)
    i, j = 0, 0
    candidateKeys = []
    while i < plainCount and j < cypherCount:
        encrypted, decrypted = plainIntermediates[i][0], cypherIntermediates[j][0]
        if encrypted < decrypted:
            i += 1
        elif encrypted > decrypted:
            j += 1
        else:
            testCypher = double_present24(plainIntermediates[i][1], cypherIntermediates[j][1], plain)
            if testCypher == cypher:
                candidateKeys.append((plainIntermediates[i][1], cypherIntermediates[j][1]))
            i += 1
            j += 1
    return candidateKeys


@njit
def mitm_attack_present24(plain1, cypher1, plain2, cypher2):
    """ Perform a meet-in-the-middle attack on the PRESENT24 cipher to find candidate keys.
    """
    plainIntermediate, cypherIntermediate = generate_intermediate_states(plain1, cypher1)
    plainIntermediate.sort()
    cypherIntermediate.sort()

    candidateKeys = search_candidates(plainIntermediate, cypherIntermediate, plain2, cypher2)
    output(plain1, cypher1, plain2, cypher2, candidateKeys)


@njit
def output(plain1, cypher1, plain2, cypher2, candidateKeys):
    print(f"Plain-cypher used for the MitM: ({int_hex(plain1)},",
          f"{int_hex(cypher1)}) and ({int_hex(plain2)}, {int_hex(cypher2)})")
    if not candidateKeys:
        print("No candidate keys found.")
    else:
        print("Candidate keys found:")
        for key1, key2 in candidateKeys:
            print(f"- ({int_hex(key1)}, {int_hex(key2)})")


@njit
def int_hex(num):
    hexChars = "0123456789abcdef"
    hexa = ""
    while num > 0:
        hexa = hexChars[num & 0b1111] + hexa
        num = num // 16
    return "0x" + hexa


if __name__ == '__main__':
    plain1, cypher1 = 0xd41330, 0x2f4a58
    plain2, cypher2 = 0x9d0af2, 0x57c9d6

    start = process_time()
    res = mitm_attack_present24(plain1, cypher1, plain2, cypher2)
    print("Durée totale:", process_time() - start)
