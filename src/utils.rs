use base64::{engine::general_purpose, Engine as _};
use hex;
use rand::Rng;
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;
use std::{iter, str};

use crate::error::CryptoError;

#[derive(Debug, Clone)]
pub struct Bytes(Vec<u8>);

impl Bytes {
    pub fn from_hex(hex: &str) -> Self {
        Bytes(hex::decode(hex).unwrap())
    }

    pub fn bytes(&self) -> &[u8] {
        self.0.as_slice()
    }

    pub fn new() -> Self {
        Bytes(vec![])
    }

    pub fn from_byte(byte: u8) -> Self {
        Bytes(vec![byte])
    }

    // Construct another block by collecting every frequency bytes
    pub fn transpose(&self, frequency: usize, start: usize) -> Self {
        Bytes(
            self.0
                .iter()
                .skip(start)
                .step_by(frequency)
                .cloned()
                .collect(),
        )
    }

    pub fn count_ones(&self) -> u32 {
        self.0.iter().map(|byte| byte.count_ones()).sum()
    }

    pub fn extend(&mut self, other: &Bytes) {
        self.0.extend(other.0.clone());
    }

    pub fn from_str(slice: &str) -> Self {
        Bytes(slice.as_bytes().to_vec())
    }

    pub fn from_base64(input: &str) -> Self {
        Bytes(general_purpose::STANDARD.decode(input).unwrap())
    }

    pub fn to_base64(&self) -> String {
        general_purpose::STANDARD_NO_PAD.encode(&self.0)
    }

    pub fn block(&self, start: usize, end: usize) -> Self {
        let slice = &self.0[start..end];
        Bytes(slice.to_vec())
    }

    pub fn display(&self) -> Option<String> {
        Some(String::from_utf8_lossy(&self.0).into())
    }

    pub fn from_base64_file<P>(filename: P) -> Self
    where
        P: AsRef<Path>,
    {
        let mut content = String::new();
        let lines = read_lines(filename).unwrap();
        for line in lines {
            if let Ok(ip) = line {
                content.push_str(&ip)
            }
        }
        Bytes::from_base64(&content)
    }

    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }

    pub fn xor(&self, other: &Bytes) -> Bytes {
        Bytes(
            self.0
                .iter()
                .zip(other.0.iter().cycle().take(self.0.len()))
                .map(|(&x1, &x2)| x1 ^ x2)
                .collect(),
        )
    }
}
pub fn hex_to_bytes(hex: &str) -> Vec<u8> {
    hex::decode(hex).unwrap()
}

pub fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

impl IntoIterator for Bytes {
    type Item = u8;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

pub fn break_single_char_xor(bytes: &[u8]) -> Vec<u8> {
    let mut counts: HashMap<u8, u8> = HashMap::new();
    let mut max_count = (0, 0);
    for byte in bytes.clone().into_iter() {
        let new_count = counts.entry(*byte).or_default();
        *new_count += 1;
        if new_count > &mut max_count.0 {
            max_count = (*new_count, *byte);
        }
    }
    let mask = xor(&[' ' as u8], &[max_count.1]);
    // Bytes::from_byte(' ' as u8).xor(&Bytes::from_byte(max_count.1));
    mask
}

pub fn read_base64_file<P>(filename: P) -> Vec<u8>
where
    P: AsRef<Path>,
{
    let mut content = String::new();
    let lines = read_lines(filename).unwrap();
    for line in lines {
        if let Ok(ip) = line {
            content.push_str(&ip)
        }
    }
    general_purpose::STANDARD.decode(content).unwrap()
}

pub fn hamming_distance(a: &[u8], b: &[u8]) -> u32 {
    let xored = xor(a, b);
    xored.iter().map(|byte| byte.count_ones()).sum()
}

pub fn random_bytes_16() -> Vec<u8> {
    rand::thread_rng().gen::<[u8; 16]>().to_vec()
}

pub fn coin_flip() -> bool {
    rand::thread_rng().gen::<bool>()
}

pub fn pad_to(bytes: &[u8], size: usize) -> Vec<u8> {
    let mut res = bytes.to_vec();
    let len = bytes.len();
    if len < size {
        res.extend::<Vec<u8>>(iter::repeat((size - len) as u8).take(size - len).collect());
    }
    res
}

pub fn random_bytes_range(min: usize, max: usize) -> Vec<u8> {
    let bytes = random_bytes_16();
    let num_bytes = rand::thread_rng().gen_range(min..max + 1);
    bytes[0..num_bytes].to_vec()
}

pub fn random_index(min: usize, max: usize) -> usize {
    rand::thread_rng().gen_range(min..max + 1)
}

pub fn strip_padding_bytes(pt: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut truncation_point = pt.len() - 1;
    let mut padding_val = None;
    while truncation_point > 0 {
        let char = pt[truncation_point];
        if char > 19 {
            break;
        }
        truncation_point -= 1;
        if let Some(val) = padding_val {
            if val != char {
                return Err(CryptoError(
                    "Invalid padding detected, padding inconsistent".into(),
                ));
            }
        } else {
            padding_val = Some(char);
        }
    }
    let num_padding_bytes = pt.len() - truncation_point - 1;
    if let Some(val) = padding_val {
        if val != num_padding_bytes as u8 {
            return Err(CryptoError(
                "Invalid padding detected, incorrect number of padding bytes".into(),
            ));
        }
    }
    Ok(pt[0..truncation_point + 1].to_vec())
}

pub fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter()
        .zip(b.iter().cycle().take(a.len()))
        .map(|(&x1, &x2)| x1 ^ x2)
        .collect()
}

pub fn from_base64(input: &str) -> Vec<u8> {
    general_purpose::STANDARD.decode(input).unwrap()
}

pub fn from_hex(hex: &str) -> Vec<u8> {
    hex::decode(hex).unwrap()
}

pub fn display(input: &[u8]) -> String {
    String::from_utf8_lossy(input).into()
}

pub fn from_base64_file<P>(filename: P) -> Vec<u8>
where
    P: AsRef<Path>,
{
    let mut content = String::new();
    let lines = read_lines(filename).unwrap();
    for line in lines {
        if let Ok(ip) = line {
            content.push_str(&ip)
        }
    }
    from_base64(&content)
}

// Construct another block by collecting every frequency bytes
pub fn transpose(bytes: &[u8], frequency: usize, start: usize) -> Vec<u8> {
    bytes
        .iter()
        .skip(start)
        .step_by(frequency)
        .cloned()
        .collect()
}
