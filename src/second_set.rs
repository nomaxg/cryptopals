#[cfg(test)]
mod second_set {
    const CONSTANT_KEY: [u8; 16] = [16; 16];
    use std::collections::HashMap;

    use crate::{
        aes::{aes_decrypt, aes_encrypt, AESMode},
        error::CryptoError,
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
        if total_score > 60 {
            mode = AESMode::EBC;
        } else {
            mode = AESMode::CBC;
        }
        assert!(mode == AESMode::EBC);

        let mut discovered_bytes = vec![];

        for key_index in 0..key_size {
            // Now lets get the first byte
            let mut short_string = vec!['A' as u8].repeat(key_size - 1 - key_index);
            let encrypted_byte =
                encryption_oracle_consistent(&short_string)[0..key_size - 1].to_vec();
            // short_string.pop();
            // let second_encrypted_byte = encryption_oracle_consistent(&short_string)[key_size - 1];
            // short_string.push('A' as u8);
            short_string.extend(discovered_bytes.clone());
            let mut map: HashMap<Vec<u8>, char> = HashMap::new();
            for i in 0..255 {
                short_string.push(i);
                let output_bytes =
                    encryption_oracle_consistent(&short_string)[0..key_size - 1].to_vec();
                map.insert(output_bytes, i as char);
                short_string.pop();
            }
            let byte = map.get(&encrypted_byte).expect("elem not found");
            discovered_bytes.push(byte.clone() as u8);
        }
        dbg!(discovered_bytes
            .iter()
            .map(|val| *val as char)
            .collect::<Vec<char>>());
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
        aes_encrypt(&plaintext, AESMode::EBC, &key)
    }

    #[test]
    pub fn test_collision() {
        let str1 = b"AAAAAAAAAAAAAAAo";
        let str2 = b"AAAAAAAAAAAAAAA%";
        let c1 = encryption_oracle_consistent(str1);
        let c2 = encryption_oracle_consistent(str2);
        dbg!(c1[0]);
        dbg!(c2[0]);
    }

    // Given foo=bar&baz=qux&zap=zazzle
    // Produces:
    // {
    //  foo: 'bar',
    //  baz: 'qux',
    //  zap: 'zazzle'
    // }
    pub fn kv_parse(string: &str) {
        let split = string.split("&").map(|kv| kv.split("="));
        println!("{{");
        for param in split {
            let params = param.collect::<Vec<&str>>();
            let (key, value) = (params[0], params[1]);
            println!("\t{}: '{}'", key, value);
        }
        println!("}}");
    }

    pub fn profile_for(email: &str) -> String {
        ["email=", email, "&uid=10&role=user"].concat()
    }

    pub fn encrypt_profile(email: &str) -> Vec<u8> {
        let key = CONSTANT_KEY;
        aes_encrypt(profile_for(email).as_bytes(), AESMode::EBC, &key)
    }

    pub fn decrypt_profile(ciphertext: &[u8]) -> String {
        let key = CONSTANT_KEY;
        display(&aes_decrypt(ciphertext, AESMode::EBC, &key))
            .unwrap()
            .to_string()
    }

    pub fn strip_padding(pt: &str) -> Result<String, CryptoError> {
        let mut truncation_point = pt.len() - 1;
        let bytes = pt.as_bytes();
        while truncation_point > 0 {
            let char = bytes[truncation_point];
            if char > 19 {
                break;
            } else if char != 4 {
                return Err(CryptoError("Invalid padding detected".into()));
            }
            truncation_point -= 1;
        }
        Ok(display(&bytes[0..truncation_point + 1])
            .unwrap()
            .to_string())
    }

    #[test]
    pub fn padding_validation() {
        let str1 = "ICE ICE BABY\x04\x04\x04\x04";
        let str2 = "ICE ICE BABY\x05\x05\x05\x05";
        let str3 = "ICE ICE BABY\x01\x02\x03\x04";
        let res1 = strip_padding(str1);
        let res2 = strip_padding(str2);
        let res3 = strip_padding(str3);
        assert!(res1 == Ok("ICE ICE BABY".into()));
        assert!(res2 == Err(CryptoError("Invalid padding detected".into())));
        assert!(res3 == Err(CryptoError("Invalid padding detected".into())));
    }

    #[test]
    pub fn cut_and_paste() {
        let email = "aaaaaaaaaaadmin\u{4}\u{4}\u{4}\u{4}\u{4}\u{4}\u{4}\u{4}\u{4}\u{4}\u{4}\u{4}bb";
        let encrypted_profile = encrypt_profile(email);
        dbg!(encrypted_profile.len());
        let altered_ciphertext = [&encrypted_profile[0..48], &encrypted_profile[16..32]].concat();
        let decrypted = decrypt_profile(&altered_ciphertext);
        kv_parse(&decrypted);
    }
}
