extern crate wasm_bindgen;

use wasm_bindgen::prelude::*;

// These constants are constant in Chromium code. Not configurable, just used for seeing hashes.
const HASHES: usize = 5;
const PRIMES: [u64; HASHES] = [0x3FB75161, 0xAB1F4E4F, 0x82675BC5, 0xCD924D35, 0x81ABE279];
const RANDOM_EVN: [u64; HASHES] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
const RANDOM_ODD: [u64; HASHES] = [0xB4663807, 0xCC322BF5, 0xD4F91BBD, 0xA7BEA11D, 0x8F462907];

#[wasm_bindgen]
pub fn hash(input: &[u8], output: &mut [u8]) {
    let mut hashes: [u64; HASHES] = [0, 0, 0, 0, 0];
    let mut zi: [u64; HASHES] = [1, 1, 1, 1, 1];

    let full_bytes = input.len() - (input.len() % 4);
    let mut current = 0;
    for i in (0..full_bytes).step_by(4) {
        let v: u32 = input[i] as u32 | (input[i + 1] as u32) << 8 | ((input[i + 2] as u32) << 16) | ((input[i + 3] as u32) << 24);
        let xi: u64 = (v as u64) * RANDOM_ODD[current] & 0x7FFFFFFF;
        hashes[current] = (hashes[current] + zi[current] * xi) % PRIMES[current];
        zi[current] = (zi[current] * RANDOM_EVN[current]) % PRIMES[current];
        current = if current == HASHES - 1 { 0 } else { current + 1 };
    }

    if full_bytes != input.len() {
        let mut v: u32 = 0;
        for i in full_bytes..input.len() {
            v <<= 8;
            v |= input[i] as u32;
        }

        let xi: u64 = (v as u64) * RANDOM_ODD[current] & 0x7FFFFFFF;
        hashes[current] = (hashes[current] + zi[current] * xi) % PRIMES[current];
        zi[current] = (zi[current] * RANDOM_EVN[current]) % PRIMES[current];
    }

    for i in 0..HASHES {
        let v = (hashes[i] + zi[i] * (PRIMES[i] - 1)) % PRIMES[i];
        let hi = i * 4;
        output[hi + 0] = (v >> 24) as u8;
        output[hi + 1] = (v >> 16) as u8;
        output[hi + 2] = (v >> 8) as u8;
        output[hi + 3] = (v >> 0) as u8;
    }
}
