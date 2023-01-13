use base64::{engine::general_purpose, Engine as _};
use hex;
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;
use std::str;

#[derive(Debug, Clone)]
pub struct Bytes(Vec<u8>);

impl Bytes {
    pub fn from_hex(hex: &str) -> Self {
        Bytes(hex::decode(hex).unwrap())
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

    pub fn display(&self) -> Option<&str> {
        if let Ok(string) = str::from_utf8(&self.0) {
            return Some(string);
        } else {
            return None;
        }
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
        dbg!(&content);
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

pub fn break_single_char_xor(bytes: &Bytes) -> Bytes {
    let mut counts: HashMap<u8, u8> = HashMap::new();
    let mut max_count = (0, 0);
    for byte in bytes.clone().into_iter() {
        let new_count = counts.entry(byte).or_default();
        *new_count += 1;
        if new_count > &mut max_count.0 {
            max_count = (*new_count, byte);
        }
    }
    let mask = Bytes::from_byte(' ' as u8).xor(&Bytes::from_byte(max_count.1));
    dbg!(bytes.xor(&mask).display());
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

pub fn hamming_distance(a: &Bytes, b: &Bytes) -> u32 {
    let xored = a.xor(b);
    xored.count_ones()
}

pub fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter()
        .zip(b.iter().cycle().take(b.len()))
        .map(|(&x1, &x2)| x1 ^ x2)
        .collect()
}

pub fn display(bytes: &[u8]) -> Option<&str> {
    if let Ok(string) = str::from_utf8(bytes) {
        return Some(string);
    } else {
        return None;
    }
}
