const BLOCK_SIZE: usize = 16;
use aes::cipher::BlockEncrypt;
use aes::cipher::{generic_array::GenericArray, BlockDecrypt, KeyInit};
use aes::Aes128;
use std::convert::TryInto;

use crate::utils::{pad_to, xor};

#[derive(PartialEq, Debug)]
pub enum AESMode {
    EBC,
    CBC,
}

pub fn aes_encrypt(data: &[u8], mode: AESMode, key: &[u8]) -> Vec<u8> {
    let cipher = Aes128::new(key.into());
    let mut encrypted = vec![];
    let mut iv_block = ['0' as u8; BLOCK_SIZE];
    for chunk in data.chunks(BLOCK_SIZE) {
        let slice: [u8; BLOCK_SIZE];
        let padded = pad_to(chunk, BLOCK_SIZE);
        if mode == AESMode::CBC {
            slice = xor(&padded, &iv_block).try_into().expect("Cant fit here")
        } else {
            slice = padded.try_into().expect("Cant fit here");
        }

        let mut block = GenericArray::from(slice);
        cipher.encrypt_block(&mut block);
        encrypted.extend(block);
        iv_block = block.into();
    }
    encrypted
}

pub fn aes_decrypt(data: &[u8], mode: AESMode, key: &[u8]) -> Vec<u8> {
    let cipher = Aes128::new(key.into());
    let mut decrypted = vec![];
    let mut iv_block = ['0' as u8; 16];
    for chunk in data.chunks(BLOCK_SIZE) {
        let slice: [u8; 16] = chunk.try_into().unwrap();
        let next_iv = slice.clone();
        let mut block = GenericArray::from(slice);
        cipher.decrypt_block(&mut block);
        let decrypted_block;
        if mode == AESMode::CBC {
            decrypted_block = xor(&block, &iv_block);
        } else {
            decrypted_block = block.to_vec();
        }
        decrypted.extend(decrypted_block.clone());
        iv_block = next_iv;
    }
    decrypted
}

pub fn ctr_encrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    ctr_stream(data, key)
}

pub fn ctr_decrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    ctr_stream(data, key)
}

fn ctr_stream(data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut ctr_vec = [0; BLOCK_SIZE];
    let mut output = vec![];
    let mut ctr = 0;
    for chunk in data.chunks(BLOCK_SIZE) {
        ctr_vec[8] = ctr;
        let mask = aes_encrypt(&ctr_vec, AESMode::EBC, key);
        let xored = xor(&chunk, &mask);
        output.extend(xored);
        ctr += 1;
    }
    output
}
