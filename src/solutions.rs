#[cfg(test)]
mod first_set {

    use crate::aes::{aes_decrypt, AESMode};
    use crate::utils::*;
    use std::collections::HashMap;
    use std::str;

    // Challenge Set 1
    #[test]
    pub fn hex_to_base64() {
        // Always operate on raw bytes, only use base64 and such for formatting
        let challenge = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
        let res = Bytes::from_hex(challenge).to_base64();
        assert!(res == expected);
    }

    #[test]
    pub fn fixed_xor() {
        let first = "1c0111001f010100061a024b53535009181c";
        let second = "686974207468652062756c6c277320657965";
        let expected = "746865206b696420646f6e277420706c6179";
        assert!(
            Bytes::from_hex(first)
                .xor(&Bytes::from_hex(second))
                .to_hex()
                == expected,
        )
    }

    #[test]
    pub fn single_byte_xor() {
        let input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
        break_single_char_xor(&Bytes::from_hex(&input));
    }

    #[test]
    pub fn detect_single_char_xor() {
        if let Ok(lines) = read_lines("./4.txt") {
            // Consumes the iterator, returns an (Optional) String
            for line in lines {
                if let Ok(ip) = line {
                    let bytes = Bytes::from_hex(&ip);
                    break_single_char_xor(&bytes);
                }
            }
        } else {
            dbg!("couldn't find file");
        }
    }

    #[test]
    pub fn repeating_key_xor() {
        let key = "ICE";
        let input = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
        let res = Bytes::from_str(input).xor(&Bytes::from_str(key));

        let expected =
            "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
        assert!(res.to_hex() == expected);
    }

    #[test]
    pub fn test_hamming_distance() {
        let a = Bytes::from_str("this is a test");
        let b = Bytes::from_str("wokka wokka!!!");
        let expected_hamming_distance = 37;
        let hamming_distance = hamming_distance(a.bytes(), b.bytes());
        assert!(expected_hamming_distance == hamming_distance);
    }

    #[test]
    pub fn break_repeating_key_xor() {
        let encrypted = Bytes::from_base64_file("./6.txt");
        let mut key = Bytes::new();
        let key_size = 29;
        // Try KEYSIZE values between 2 and 40
        for i in 2..40 {
            let first_block = encrypted.block(0, i);
            let second_block = encrypted.block(i, 2 * i);
            // let third_block = encrypted.block(2 * i, 3 * i);
            // let fourth_block = encrypted.block(3 * i, 4 * i);
            let first_score =
                hamming_distance(first_block.bytes(), second_block.bytes()) / (i as u32);
            let second_score =
                hamming_distance(first_block.bytes(), second_block.bytes()) / (i as u32);
            let score = (first_score + second_score) / 2;
            dbg!(&score);
        }
        for i in 0..key_size {
            let transposed = encrypted.transpose(key_size, i);
            let block_key = break_single_char_xor(&transposed);
            key.extend(&block_key);
        }
        dbg!(encrypted.xor(&key).display());
    }

    #[test]
    pub fn aes_ecb_mode() {
        let ciphertext = read_base64_file("./7.txt");
        let key = b"YELLOW SUBMARINE";
        let decrypted = aes_decrypt(&ciphertext, AESMode::EBC, key);
        let decrypted_text = str::from_utf8(&decrypted).unwrap();
        dbg!(decrypted_text);
    }

    #[test]
    pub fn detect_aes_in_ecb() {
        if let Ok(lines) = read_lines("./8.txt") {
            let mut candidate = vec![];
            let mut max_similarity = 0;
            // Consumes the iterator, returns an (Optional) String
            for line in lines {
                if let Ok(ip) = line {
                    let bytes = hex_to_bytes(&ip);
                    let mut counts: HashMap<u8, u8> = HashMap::new();
                    let mut max_count = (0, 0);
                    for byte in bytes.clone().into_iter() {
                        let new_count = counts.entry(byte).or_default();
                        *new_count += 1;
                        if new_count > &mut max_count.0 {
                            max_count = (*new_count, byte);
                        }
                    }
                    if max_count.0 > max_similarity {
                        candidate = bytes;
                        max_similarity = max_count.0;
                    }
                }
            }
            println!("Candidate vec has most repeated bytes: {}", max_similarity);
            dbg!(candidate);
        } else {
            dbg!("couldn't find file");
        }
    }
}
