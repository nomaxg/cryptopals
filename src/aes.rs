const BLOCK_SIZE: usize = 16;
use aes::cipher::BlockEncrypt;
use aes::cipher::{generic_array::GenericArray, BlockDecrypt, KeyInit};
use aes::Aes128;
use std::convert::TryInto;

use crate::utils::{display, xor};

#[derive(PartialEq)]
pub enum AESMode {
    EBC,
    CBC,
}

pub fn aes_encrypt(data: &[u8], mode: AESMode, key: &[u8]) -> Vec<u8> {
    let cipher = Aes128::new(key.into());
    let mut encrypted = vec![];
    let mut iv_block = ['0' as u8; 16];
    for chunk in data.chunks(BLOCK_SIZE) {
        let slice: [u8; 16];
        if mode == AESMode::CBC {
            slice = xor(chunk, &iv_block).try_into().unwrap()
        } else {
            slice = chunk.try_into().unwrap();
        }

        let mut block = GenericArray::from(slice);
        cipher.encrypt_block(&mut block);
        encrypted.extend(block);
        iv_block = slice;
    }
    encrypted
}

pub fn aes_decrypt(data: &[u8], mode: AESMode, key: &[u8]) -> Vec<u8> {
    let cipher = Aes128::new(key.into());
    let mut decrypted = vec![];
    let mut iv_block = ['0' as u8; 16];
    for chunk in data.chunks(BLOCK_SIZE) {
        let slice: [u8; 16] = chunk.try_into().unwrap();
        let mut block = GenericArray::from(slice);
        cipher.decrypt_block(&mut block);
        let decrypted_block;
        if mode == AESMode::CBC {
            decrypted_block = xor(&block, &iv_block);
        } else {
            decrypted_block = block.to_vec();
        }
        let display = display(&decrypted_block);
        dbg!(display);
        decrypted.extend(decrypted_block.clone());
        iv_block = decrypted_block.try_into().unwrap();
    }
    decrypted
}
