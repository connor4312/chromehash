extern crate wasm_bindgen;

use wasm_bindgen::prelude::*;
use std::cmp;

// These constants are constant in Chromium code. Not configurable, just used for seeing hashes.
const HASHES: usize = 5;
const U32_SIZE: usize = 4;
const PRIMES: [u64; HASHES] = [0x3FB75161, 0xAB1F4E4F, 0x82675BC5, 0xCD924D35, 0x81ABE279];
const RANDOM_EVN: [u64; HASHES] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
const RANDOM_ODD: [u64; HASHES] = [0xB4663807, 0xCC322BF5, 0xD4F91BBD, 0xA7BEA11D, 0x8F462907];

#[wasm_bindgen]
pub struct Hasher {
    hashes: [u64; HASHES],
    zi: [u64; HASHES],
    current: usize,
    next_u32: u32,
    next_len: usize,
}

#[wasm_bindgen]
impl Hasher {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Hasher {
        Hasher {
            hashes: [0; HASHES],
            zi: [1; HASHES],
            current: 0,
            next_u32: 0,
            next_len: U32_SIZE,
        }
    }

    pub fn update(&mut self, mut input: &[u8]) {
        let offset = cmp::min(U32_SIZE - self.next_len, input.len());
        self.digest_raw(&input[0..offset]);
        input = &input[offset..];

        // WebAssembly's numbers are little endian, which is what we need for
        // hash input. Thus we can just look at the remaining (full) bytes
        // in the slice and treat them as u32's.
        let remaining = (input.len() / U32_SIZE) * U32_SIZE;
        for v in (0..remaining).step_by(U32_SIZE) {
            self.add_u32(unsafe { *std::mem::transmute::<&u8, &u32>(&input[v]) });
        }

        self.digest_raw(&input[remaining..]);
    }

    pub fn digest(&mut self, output: &mut [u8]) {
        if self.next_len != U32_SIZE {
            self.add_u32(swap_u32(self.next_u32));
        }

        for i in 0..HASHES {
            let v = (self.hashes[i] + self.zi[i] * (PRIMES[i] - 1)) % PRIMES[i];
            let hi = i * 4;
            output[hi + 0] = (v >> 24) as u8;
            output[hi + 1] = (v >> 16) as u8;
            output[hi + 2] = (v >> 8) as u8;
            output[hi + 3] = (v >> 0) as u8;
        }
    }

    #[inline(always)]
    fn digest_raw(&mut self, input: &[u8]) {
        for &v in input {
            self.next_u32 >>= 8;
            self.next_u32 |= (v as u32) << 24;
            self.next_len -= 1;

            if self.next_len == 0 {
                self.add_u32(self.next_u32);
                self.next_u32 = 0;
                self.next_len = U32_SIZE;
            }
        }
    }

    #[inline(always)]
    fn add_u32(&mut self, v: u32) {
        let xi: u64 = (v as u64) * RANDOM_ODD[self.current] & 0x7FFFFFFF;
        self.hashes[self.current] =
            (self.hashes[self.current] + self.zi[self.current] * xi) % PRIMES[self.current];
        self.zi[self.current] =
            (self.zi[self.current] * RANDOM_EVN[self.current]) % PRIMES[self.current];

        if self.current == HASHES - 1 {
            self.current = 0
        } else {
            self.current += 1;
        };
    }
}

// swaps the bytes in a u32
#[inline(always)]
fn swap_u32(value: u32) -> u32 {
    (value & 0xFF) << 24 | ((value >> 8) & 0xFF) << 16 | ((value >> 16) & 0xFF) << 8 | (value >> 24)
}
