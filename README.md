# PRESENT24 Meet-In-The-Middle Attack


This project was developed as part of a course at **Université de Versailles Saint-Quentin-en-Yvelines (UVSQ)**.


## Description

This program implements in python encryption, decryption, and a **Meet-In-The-Middle (MitM) attack** (in python and rust) on the simplified **PRESENT24** cipher. PRESENT24 is a reduced version of the **PRESENT** encryption algorithm that operates on 24-bit inputs and keys. The program allows users to:

- Encrypt a 24-bit plaintext with a 24-bit key.
- Decrypt a 24-bit ciphertext with a 24-bit key.
- Perform a Meet-In-The-Middle (MitM) attack using two known plaintext-ciphertext pairs.

The Meet-In-The-Middle attack can be performed using either a standard or an optimized version using numba and better function calls.


## Requirements

The project requires **Python $\ge$ 3.9** and the dependencies listed in `requirements.txt`.
Notably it requires the `numba` module, which is used to speed up the program by using Just-In-Time (JIT) compilation.
To install them, you can run:

```bash
% pip install -r requirements.txt
```


## Usage

The program supports the following commands:

1. **Encrypt a message**
Encrypts a 24-bit plaintext using a 24-bit key.

```bash
% python main.py encrypt -p <plaintext> -k <key>
```

- -p, --plain: Plaintext to encrypt (in hexadecimal format).
- -k, --key: Key to encrypt the plaintext (in hexadecimal format).

2. **Decrypt a message**
Decrypts a 24-bit ciphertext using a 24-bit key.

```bash
% python main.py decrypt -c <ciphertext> -k <key>
```

- -c, --cypher: Ciphertext to decrypt (in hexadecimal format).
- -k, --key: Key of the ciphertext (in hexadecimal format).

3. **Meet-In-The-Middle Attack**
Performs a MitM attack on the PRESENT24 cipher using two known plaintext-ciphertext pairs, taking $\approx$ 45min.

```bash
% python main.py attack -p1 <plaintext1> -c1 <ciphertext1> -p2 <plaintext2> -c2 <ciphertext2>
```

- -p1, --plain1: First plaintext (in hexadecimal format).
- -c1, --cypher1: First ciphertext (in hexadecimal format).
- -p2, --plain2: Second plaintext (in hexadecimal format).
- -c2, --cypher2: Second ciphertext (in hexadecimal format).

4. **Optimized Meet-In-The-Middle Attack**
Performs a MitM attack faster than the original one, taking $\approx$ 30s.

```bash
% python main.py fast -p1 <plaintext1> -c1 <ciphertext1> -p2 <plaintext2> -c2 <ciphertext2>
```

- The arguments are the same as for the standard attack.


## Examples

1. Encryption Example:

```bash
% python main.py e -p 0xf955b9 -k d1bd2d
```
Encrypts the plaintext 0xf955b9 with the key 0xd1bd2d.

2. Decryption Example:

```bash
% python main.py d -c 47a929 -k 0xd1bd2d
```
Decrypts the ciphertext 0x47a929 with the key 0xd1bd2d.

3. Standard MitM Attack Example:

```bash
% python main.py a -p1 0xd41330 -c1 2f4a58 -p2 0x9d0af2 -c2 0x57c9d6
```

4. Optimized MitM Attack Example:

```bash
% python main.py fast -p1 0xd41330 -c1 0x2f4a58 -p2 9d0af2 -c2 0x57c9d6
```
Output:
```bash
% python main.py f
Starting MitM attack.
Plain-cypher used for the MitM: (0xd41330, 0x2f4a58) and (0x9d0af2, 0x57c9d6)
Candidate keys found:
- (0x3d93b5, 0x3aa01a)

Total Meet-in-the-Middle attack time: 30.9s
```


## Default Values

If no values are provided, the program uses the following as defaults:
- For the encryption/decryption:
  - Plaintext: 0xf955b9
  - Key: 0xd1bd2d
  - Cypher: 0x47a929
- For the attacks:
  - Plaintext 1 (PLAIN1): 0xd41330
  - Ciphertext 1 (CYPHER1): 0x2f4a58
  - Plaintext 2 (PLAIN2): 0x9d0af2
  - Ciphertext 2 (CYPHER2): 0x57c9d6


## Rust Implementation

To have a reference time, the attack has been implemented in rust without much parallelism in order to be a fair comparison.


### Rust Usage

The ```--realease ``` compilation option is recommended, because it significantly reduces the attack time.

```bash
% cargo run [--release] [-- [--P <HEX>] [--cipher1 <HEX>] [--plain2 <HEX>] [--c <HEX>]]
```
With ```<HEX>``` a 24-bit hexadecimal number, e.g. ```0x1A2B3C``` or ```123ABC```.


### Comparison

The time using the python version was 31s, with the rust one we managed to reach 4s (and 0.8s with parallelism).


| Python | Rust |
|:------:|:----:|
|   31s  |  4s  |
