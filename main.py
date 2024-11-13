""" PRESENT24 Meet-In-The-Middle attack.
"""

import sys
import argparse
import functools
from time import process_time

from src.python.original.encryption import encryption
from src.python.original.decryption import decryption
from src.python.original.attack import attack_2present24
from src.python.optimized.attack import mitm_attack_present24

# Default values of plaintext-ciphertext pairs for the MitM and test values for encryption-decryption.
PLAIN1, CYPHER1 = 0xd41330, 0x2f4a58
PLAIN2, CYPHER2 = 0x9d0af2, 0x57c9d6
TESTS_VALUES = [{"plain": 0, "key": 0, "cypher": 0xbb57e6},
                {"plain": 0xffffff, "key": 0, "cypher": 0x739293},
                {"plain": 0, "key": 0xffffff, "cypher": 0x1b56ce},
                {"plain": 0xf955b9, "key": 0xd1bd2d, "cypher": 0x47a929}]


def call_encrypt(args):
    print("Starting encryption.")
    cypher = encryption(args.key, args.plain)
    print(f"The plaintext {args.plain:#08x} has been encrypted with the key {args.key:#08x} in: {cypher:#08x}.")


def call_decrypt(args):
    print("Starting decryption.")
    plain = decryption(args.key, args.cypher)
    print(f"The plaintext {args.cypher:#08x} has been encrypted with the key {args.key:#08x} in: {plain:#08x}.")


def call_attack(args):
    print("Starting MitM attack.")
    start = process_time()
    attack_2present24(args.plain1, args.cypher1, args.plain2, args.cypher2)
    print(f"\nTotal Meet-in-the-Middle attack time: {(process_time() - start):.1f}s")


def call_optimized_attack(args):
    print("Starting MitM attack.")
    start = process_time()
    mitm_attack_present24(args.plain1, args.cypher1, args.plain2, args.cypher2)
    print(f"\nTotal Meet-in-the-Middle attack time: {(process_time() - start):.1f}s")


def main():
    parser = argparse.ArgumentParser(
        description="Chiffrement PRESENT24 "
        "(Version simplifier du chiffrement PRESENT sur 24 bit)"
    )
    subparsers = parser.add_subparsers(help='commandes')
    encryption_parser = subparsers.add_parser(
        'encrypt',
        aliases=['e'],
        help="Encrypt a 24 bit message with a key using PRESENT24",
        description="Encrypt a 24 bit message with a key using PRESENT24"
    )
    encryption_parser.add_argument('-p', '--plain', type=functools.partial(int, base=16), help="Plaintext to encrypt (in hex format)", default=TESTS_VALUES[3]["plain"])
    encryption_parser.add_argument('-k', '--key', type=functools.partial(int, base=16), help="Key to encrypt the plaintext (in hex format)", default=TESTS_VALUES[3]["key"])
    encryption_parser.set_defaults(func=call_encrypt)

    decryption_parser = subparsers.add_parser(
        'decrypt',
        aliases=['d'],
        help="Decrypt a 24 bit cypher with a key using PRESENT24",
        description="Decrypt a 24 bit cypher with a key using PRESENT24"
    )
    decryption_parser.add_argument('-c', '--cypher', type=functools.partial(int, base=16), help="Cyphertext to decrypt (in hex format)", default=TESTS_VALUES[3]["cypher"])
    decryption_parser.add_argument('-k', '--key', type=functools.partial(int, base=16), help="Key of the cyphertext (in hex format)", default=TESTS_VALUES[3]["key"])
    decryption_parser.set_defaults(func=call_decrypt)

    attack_parser = subparsers.add_parser(
        'attack',
        aliases=['a'],
        help="Do a Meet-in-the-Middle attack on PRESENT24 using 2 (plain, cypher) pairs",
        description="Do a Meet-in-the-Middle attack on PRESENT24 using 2 (plain, cypher) pairs"
    )
    attack_parser.add_argument('-p1', '--plain1', type=functools.partial(int, base=16), help="First plaintext (in hex format)", default=PLAIN1)
    attack_parser.add_argument('-c1', '--cypher1', type=functools.partial(int, base=16), help="First plaintext (in hex format)", default=CYPHER1)
    attack_parser.add_argument('-p2', '--plain2', type=functools.partial(int, base=16), help="Second plaintext (in hex format)", default=PLAIN2)
    attack_parser.add_argument('-c2', '--cypher2', type=functools.partial(int, base=16), help="Second plaintext (in hex format)", default=CYPHER2)
    attack_parser.set_defaults(func=call_attack)

    opt_atk_parser = subparsers.add_parser(
        'fast',
        aliases=['f'],
        help="Do a Meet-in-the-Middle attack on PRESENT24 using 2 (plain, cypher) pairs (faster)",
        description="Do a Meet-in-the-Middle attack on PRESENT24 using 2 (plain, cypher) pairs (faster)"
    )
    opt_atk_parser.add_argument('-p1', '--plain1', type=functools.partial(int, base=16), help="First plaintext (in hex format)", default=PLAIN1)
    opt_atk_parser.add_argument('-c1', '--cypher1', type=functools.partial(int, base=16), help="First plaintext (in hex format)", default=CYPHER1)
    opt_atk_parser.add_argument('-p2', '--plain2', type=functools.partial(int, base=16), help="Second plaintext (in hex format)", default=PLAIN2)
    opt_atk_parser.add_argument('-c2', '--cypher2', type=functools.partial(int, base=16), help="Second plaintext (in hex format)", default=CYPHER2)
    opt_atk_parser.set_defaults(func=call_optimized_attack)

    try:
        args = parser.parse_args()
        args.func(args)
    except AttributeError:
        parser.print_usage(sys.stderr)
        sys.exit(2)


if __name__ == '__main__':
    main()
