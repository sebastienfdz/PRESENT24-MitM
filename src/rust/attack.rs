use rayon::iter::{ParallelIterator, IntoParallelIterator};
use rayon::prelude::ParallelSliceMut;

use crate::rust::key_schedule::key_schedule;


const SBOX: [u8; 16] = [0xc, 0x5, 0x6, 0xb, 0x9, 0x0, 0xa, 0xd, 0x3, 0xe, 0xf, 0x8, 0x4, 0x7, 0x1, 0x2];
const INV_SBOX: [u8; 16] = [0x5, 0xe, 0xf, 0x8, 0xc, 0x1, 0x2, 0xd, 0xb, 0x4, 0x6, 0x3, 0x0, 0x7, 0x9, 0xa];
const K: u32 = 1 << 24;


/// PRESENT24 encryption of a plaintext with a 24-bit key.
fn encrypt(round_keys: &[u32], plaintext: u32) -> u32 {
    let mut cipher = plaintext;
    for i in 0..10 {
        cipher ^= round_keys[i];
        // Substitution
        let mut temp: u32 = 0;
        for j in 0..6 {
            temp |= (SBOX[((cipher >> (j * 4)) & 0xf) as usize] as u32) << (j * 4);
        }
        cipher = temp;
        // Permutation
        temp = 0;
        for j in 0..23 {
            temp |= ((cipher >> j) & 1) << ((6 * j) % 23);
        }
        cipher = temp | (cipher & 0x800000);
    }
    cipher ^ round_keys[10]
}


/// PRESENT24 decryption of a cypher with a 24-bit key.
fn decrypt(round_keys: &[u32], ciphertext: u32) -> u32 {
    let mut plain = ciphertext ^ round_keys[10];
    for i in (0..10).rev() {
        // Inverse permutation
        let mut temp = 0;
        for j in 0..23 {
            temp |= ((plain >> j) & 1) << ((4 * j) % 23);
        }
        plain = temp | (plain & 0x800000);

        // Inverse substitution
        temp = 0;
        for j in 0..6 {
            temp |= (INV_SBOX[((plain >> (j * 4)) & 0xf) as usize] as u32) << (j * 4);
        }
        plain = temp ^ round_keys[i];
    }
    plain
}


/// 2-PRESENT24 encryption of a plaintext with a 48-bit key (k1, k2).
fn double_present24(key1: u32, key2: u32, plaintext: u32) -> u32 {
    let round_keys1 = key_schedule(key1);
    let round_keys2 = key_schedule(key2);
    encrypt(&round_keys2, encrypt(&round_keys1, plaintext))
}


/// Generate intermediate encryption and decryption lists for the MitM attack.
/// 
/// Even though for efvery master_key we calculate 2 times key_schedule(master_key) it is still faster.
/// We didn't use a better method to parallelize because it wouldn't be a fair comparison.
/// With the better parallelization we achieved 0.8s (instead of 4.0s).
fn generate_intermediate_states(plaintext: u32, ciphertext: u32) -> (Vec<(u32, u32)>, Vec<(u32, u32)>) {
    let mut plain_intermediate: Vec<_> = (0..K).into_par_iter()
        .map(|master_key| {
            let round_keys = key_schedule(master_key);
            (encrypt(&round_keys, plaintext), master_key)
        })
        .collect();

    let mut cipher_intermediate: Vec<_> = (0..K).into_par_iter()
        .map(|master_key| {
            let round_keys = key_schedule(master_key);
            (decrypt(&round_keys, ciphertext), master_key)
        })
        .collect();

    plain_intermediate.par_sort_unstable();
    cipher_intermediate.par_sort_unstable();
    (plain_intermediate, cipher_intermediate)
}


/// Find matching keys between two sorted lists of tuples.
fn search_candidates(
    plain_intermediate: &[(u32, u32)],
    cipher_intermediate: &[(u32, u32)],
    plaintext: u32,
    ciphertext: u32
) -> Vec<(u32, u32)> {
    let (plain_count, cipher_count) = (plain_intermediate.len(), cipher_intermediate.len());
    let mut candidate_keys = Vec::new();
    let mut i = 0;
    let mut j = 0;

    while i < plain_count && j < cipher_count {
        match plain_intermediate[i].0.cmp(&cipher_intermediate[j].0) {
            std::cmp::Ordering::Less => i += 1,
            std::cmp::Ordering::Greater => j += 1,
            std::cmp::Ordering::Equal => {

                let key1 = plain_intermediate[i].1;
                let key2 = cipher_intermediate[j].1;
                if double_present24(key1, key2, plaintext) == ciphertext {
                    candidate_keys.push((key1, key2));
                }
                i += 1;
                j += 1;
            }
        }
    }
    candidate_keys
}


/// Perform a meet-in-the-middle attack on the PRESENT24 cipher to find candidate keys.
pub fn mitm_attack_present24(plain1: u32, cipher1: u32, plain2: u32, cipher2: u32) {
    let (plain_intermediate, cipher_intermediate) = generate_intermediate_states(plain1, cipher1);

    let candidate_keys = search_candidates(&plain_intermediate, &cipher_intermediate, plain2, cipher2);
    output_results(plain1, cipher1, plain2, cipher2, &candidate_keys);
}


fn output_results(plain1: u32, cipher1: u32, plain2: u32, cipher2: u32, candidate_keys: &[(u32, u32)]) {
    println!(
        "Plain-cipher used for the MitM: ({:#08x}, {:#08x}) and ({:#08x}, {:#08x})",
        plain1, cipher1, plain2, cipher2
    );

    if candidate_keys.is_empty() {
        println!("No candidate keys found.");
    } else {
        println!("Candidate keys found:");
        for (key1, key2) in candidate_keys {
            println!("- ({:#08x}, {:#08x})", key1, key2);
        }
    }
}
