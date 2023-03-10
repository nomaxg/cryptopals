use std::env::temp_dir;

const W: u32 = 32;
const N: usize = 624;
const M: u32 = 397;
const R: u32 = 31;
const A: u32 = 0x9908_B0DF;
const U: u32 = 11;
const S: u32 = 7;
const F: u32 = 1812433253;
const B: u32 = 0x9D2C_5680;
const T: u32 = 15;
const C: u32 = 0xEFC6_0000;
const L: u32 = 18;
const LOWER_MASK: u32 = (1 << R) - 1;
const UPPER_MASK: u32 = !LOWER_MASK;

#[derive(Debug)]
pub struct MersenneTwister {
    pub state: [u32; N],
    pub index: usize,
}

impl MersenneTwister {
    pub fn seed(seed: u32) -> Self {
        let index = N;
        let mut state = [0; N];
        state[0] = seed;
        for i in 1..N {
            state[i] = (state[i - 1] ^ (state[i - 1] >> (W - 2)))
                .wrapping_mul(F)
                .wrapping_add(i as u32);
        }
        Self { index, state }
    }

    pub fn extract_number(&mut self) -> u32 {
        if self.index >= N {
            self.twist()
        }
        let y = temper(self.state[self.index]);
        self.index += 1;
        y
    }

    fn twist(&mut self) {
        for i in 0..N - 1 {
            let x = (self.state[i] & UPPER_MASK) | (self.state[i + 1] % (N as u32) & LOWER_MASK);
            let mut x_a = x >> 1;
            if x % 2 != 0 {
                // lowest bit of x is 1
                x_a = x_a ^ A;
            }
            self.state[i] = self.state[(i + (M as usize)) % N] ^ x_a;
        }
        self.index = 0;
        dbg!(self.state[1]);
    }
}

pub fn temper(num: u32) -> u32 {
    let mut y = num;
    y = y ^ (y >> U);
    y = y ^ ((y << S) & B);
    y = y ^ ((y << T) & C);
    y = y ^ (y >> L);
    y
}

pub fn untemper(num: u32) -> u32 {
    let mut y = num;

    y = (y & (!0 << 14)) ^ ((y >> 18) ^ y & (!0 >> 18));

    y = (y ^ (y << 15 & C)) | (y & (!0 >> 17));

    let mut temp = y & (!0 >> 25);
    for i in 1..5 {
        temp = (y ^ ((temp << 7) & B)) & (0b1111111u32 << i * 7) ^ temp;
    }
    y = temp;

    let mut temp = y & (!0 << 21);
    temp = ((y ^ (temp >> 11)) & (0b11111111111u32 << 10)) | temp;
    temp = ((y ^ (temp >> 11)) & (0b1111111111u32)) | temp;
    y = temp;

    y
}
