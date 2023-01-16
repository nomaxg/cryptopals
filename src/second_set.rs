#[cfg(test)]
mod second_set {
    const CONSTANT_KEY: [u8; 16] = [16; 16];
    use std::collections::HashMap;

    use crate::{
        aes::{aes_decrypt, aes_encrypt, AESMode},
        utils::{
            coin_flip, display, from_base64, hamming_distance, random_bytes_16, random_bytes_range,
            read_base64_file,
        },
    };

    #[test]
    pub fn implement_cbc_mode() {
        let ciphertext = read_base64_file("./10.txt");
        let key = b"YELLOW SUBMARINE";
        let decrypted = aes_decrypt(&ciphertext, AESMode::CBC, key);
        println!("Decrypted {:?}", display(&decrypted))
    }

    #[test]
    pub fn ecb_cbc_detection() {
        // let ciphertext = read_base64_file("./10.txt");
        // let key = b"YELLOW SUBMARINE";
        // let decrypted = aes_decrypt(&ciphertext, AESMode::CBC, key);
        // let text = display(&decrypted).unwrap();
        let text = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
        let ciphertext = encryption_oracle(text.as_bytes());
        let mut total_score = 0;
        for i in 1..3 {
            total_score += hamming_distance(&ciphertext[0..16], &ciphertext[16 * i..16 * i + 16]);
        }
        if total_score > 100 {
            println!("EBC detected")
        } else {
            println!("CBC detected")
        }
    }

    #[test]
    pub fn ecb_decryption() {
        // Detect key size
        let mut text = vec!['A' as u8];
        let mut size = encryption_oracle_consistent(&text).len();
        let key_size;
        loop {
            text.push('A' as u8);
            let ciphertext = encryption_oracle_consistent(&text);
            let new_size = ciphertext.len();
            if new_size != size {
                key_size = new_size - size;
                break;
            }
            size = new_size;
        }
        // Detect mode
        text = b"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX".to_vec().repeat(10);
        let ciphertext = encryption_oracle(&text);
        let mut total_score = 0;
        for i in 1..3 {
            total_score += hamming_distance(&ciphertext[0..16], &ciphertext[16 * i..16 * i + 16]);
        }
        let mode;
        dbg!(&total_score);
        if total_score > 60 {
            mode = AESMode::EBC;
        } else {
            mode = AESMode::CBC;
        }
        assert!(mode == AESMode::EBC);

        for key_index in 0..key_size {
            // Now lets get the first byte
            let mut short_string = vec!['A' as u8].repeat(key_size - 1 - key_index);
            let encrypted_byte = encryption_oracle_consistent(&short_string)[key_size - 1];
            // short_string.pop();
            // let second_encrypted_byte = encryption_oracle_consistent(&short_string)[key_size - 1];
            // short_string.push('A' as u8);
            short_string = vec!['A' as u8].repeat(key_size - 1);
            let mut map: HashMap<u8, char> = HashMap::new();
            for i in 0..255 {
                short_string.push(i);
                let byte = encryption_oracle_consistent(&short_string)[key_size - 1];
                map.insert(byte, i as char);
                short_string.pop();
            }
            println!(
                "Byte of plaintext is {}",
                map.get(&encrypted_byte).expect("elem not found")
            );
        }
        // println!(
        //     "Second of plaintext is {}",
        //     map.get(&second_encrypted_byte).expect("elem not found")
        // );
    }

    fn encryption_oracle(input: &[u8]) -> Vec<u8> {
        let key = random_bytes_16();
        let padding_before = random_bytes_range(2, 5);
        let padding_after = random_bytes_range(2, 5);
        let plaintext = [&padding_before, input, &padding_after].concat();
        let coin_flip = coin_flip();
        let mode = match coin_flip {
            true => AESMode::CBC,
            false => AESMode::EBC,
        };
        aes_encrypt(&plaintext, mode, &key)
    }

    fn encryption_oracle_consistent(input: &[u8]) -> Vec<u8> {
        let key = CONSTANT_KEY;
        let padding_str = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
        let padding_after = from_base64(&padding_str);
        let plaintext = [input, &padding_after].concat();
        aes_encrypt(&plaintext, AESMode::CBC, &key)
    }
}
