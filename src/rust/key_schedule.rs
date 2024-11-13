/// Generate round keys for the PRESENT24 cipher from the master key.
pub fn key_schedule(master_key: u32) -> [u32; 11] {
    const SBOX: [u8; 16] = [0xc, 0x5, 0x6, 0xb, 0x9, 0x0, 0xa, 0xd,
                            0x3, 0xe, 0xf, 0x8, 0x4, 0x7, 0x1, 0x2];
    const MASK_76_BITS: u128 = 0x0FFF_FFFF_FFFF_FFFF_FFFF;
    const MASK_24_BITS: u128 = 0x00FF_FFFF;
    const MASK_19_BITS: u128 = 0x0007_FFFF;
    
    // Convert master key to 80-bit equivalent.
    let mut key: u128 = (master_key as u128) << 56;
    let mut round_keys = [0u32; 11];

    for i in 1..11 {
        // Rotate left by 61 bits.
        key = ((key & MASK_19_BITS) << 61) | key >> 19;
        // S-Box substitution on most significant 4 bits.
        key = (SBOX[(key >> 76) as usize] as u128) << 76 | (key & MASK_76_BITS);
        // XOR key with the turn i.
        key ^= i << 15;
        round_keys[i as usize] = ((key >> 16) & MASK_24_BITS) as u32;
    }
    round_keys
}
