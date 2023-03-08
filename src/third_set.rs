mod third_set {
    const CONSTANT_KEY: [u8; 16] = [16; 16];
    use std::collections::HashMap;

    use crate::{
        aes::{aes_decrypt, aes_encrypt, ctr_decrypt, ctr_encrypt},
        twister::MersenneTwister,
        utils::{
            break_single_char_xor, display, from_base64, random_index, read_lines,
            strip_padding_bytes, transpose, xor, Bytes,
        },
    };
    const PLAINTEXTS: [&'static str; 40] = [
        "SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==",
        "Q29taW5nIHdpdGggdml2aWQgZmFjZXM=",
        "RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==",
        "RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=",
        "SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk",
        "T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
        "T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=",
        "UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
        "QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=",
        "T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl",
        "VG8gcGxlYXNlIGEgY29tcGFuaW9u",
        "QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==",
        "QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=",
        "QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==",
        "QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=",
        "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
        "VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==",
        "SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==",
        "SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==",
        "VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==",
        "V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==",
        "V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==",
        "U2hlIHJvZGUgdG8gaGFycmllcnM/",
        "VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=",
        "QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=",
        "VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=",
        "V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=",
        "SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==",
        "U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==",
        "U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=",
        "VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==",
        "QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu",
        "SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=",
        "VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs",
        "WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=",
        "SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0",
        "SW4gdGhlIGNhc3VhbCBjb21lZHk7",
        "SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=",
        "VHJhbnNmb3JtZWQgdXR0ZXJseTo=",
        "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
    ];

    #[test]
    pub fn twister() {
        let mut twister = MersenneTwister::seed(32);
        let mut num = twister.extract_number();
        num = twister.extract_number();
        num = twister.extract_number();
        num = twister.extract_number();
        num = twister.extract_number();
        num = twister.extract_number();
        num = twister.extract_number();
        dbg!(num);
    }

    #[test]
    pub fn break_ctr_statistically() {
        let lines = read_lines("./20.txt").unwrap();
        let mut cts = vec![];
        let mut key_size = 500;
        for line in lines {
            if let Ok(ip) = line {
                let bytes = from_base64(&ip);
                if bytes.len() < key_size {
                    key_size = bytes.len();
                }
                cts.push(bytes);
            }
        }
        for ct in &mut cts {
            ct.truncate(key_size);
        }
        let encrypted = cts.into_iter().flatten().collect::<Vec<u8>>();
        let mut key = vec![];
        for i in 0..key_size {
            let transposed = transpose(&encrypted, key_size, i);
            let block_key = break_single_char_xor(&transposed);
            key.extend(&block_key);
        }
        dbg!(display(&xor(&encrypted, &key)));
    }

    #[test]
    pub fn implement_ctr() {
        let ct =
            from_base64("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==");
        let key = b"YELLOW SUBMARINE";
        let pt = ctr_decrypt(&ct, key);
        dbg!(display(&pt));
    }

    #[test]
    pub fn break_ctr_substitution() {
        fn create_guess(guesses: &[(usize, &str, usize)], texts: &[Vec<u8>]) -> Vec<u8> {
            let mut stream = [0 as u8; 40];
            for guess in guesses {
                let decrypted = &texts[guess.0];
                let guess_bytes = xor(&decrypted, guess.1.as_bytes());
                for i in guess.2..decrypted.len() {
                    stream[i] = guess_bytes[i - guess.2];
                }
            }
            stream.to_vec()
        }

        fn evaluate_guess(stream: &[u8], texts: &[Vec<u8>]) {
            for (idx, text) in texts.iter().enumerate() {
                let pt = xor(&stream, &text);
                println!("{}:{}", idx, display(&pt[0..text.len()]));
            }
        }

        fn index_histogram(texts: &[Vec<u8>], index: usize) {
            let mut counts: HashMap<u8, u8> = HashMap::new();
            let mut max_count = (0, 0, 0);
            for (sample_index, text) in texts.iter().enumerate() {
                let byte = text[index];
                let new_count = counts.entry(byte).or_default();
                *new_count += 1;
                if new_count > &mut max_count.0 {
                    max_count = (*new_count, byte, sample_index);
                }
            }
            dbg!(max_count);
        }

        let texts = PLAINTEXTS.map(|pt| ctr_encrypt(&from_base64(pt), &CONSTANT_KEY));
        index_histogram(&texts, 0);

        let guess = create_guess(
            &[
                (30, "Th", 0),
                (2, "From", 0),
                (29, "So daring and sweet", 0),
                (18, "Her nights in argument", 0),
                (28, "So sensitive his nature", 0),
                (5, "Or polite meaningless words", 0),
                (14, "All changed, changed utterly", 0),
                (8, "And thought before I had done", 0),
                (29, "So daring and sweet his thought", 0),
                (6, "Or have lingered awhile and said", 0),
                (27, "He might have won fame in the end", 0),
                (4, "I have passed with a nod of the head", 0),
            ],
            &texts,
        );
        evaluate_guess(&guess, &texts);
    }

    // returns ciphertext and IV
    fn gen_random_cbc_encryption() -> Vec<u8> {
        let options = [
            "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
            "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
            "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
            "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
            "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
            "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
            "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
            "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
            "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
            "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
        ];
        let pt = from_base64(options[random_index(0, options.len() - 1)]);
        let ct = aes_encrypt(&pt, crate::aes::AESMode::CBC, &CONSTANT_KEY);
        ct
    }

    fn verify_padding(ct: &[u8]) -> bool {
        let pt = aes_decrypt(ct, crate::aes::AESMode::CBC, &CONSTANT_KEY);
        let res = strip_padding_bytes(&pt);
        if let Ok(stripped) = res {
            stripped.len() != ct.len()
        } else {
            return false;
        }
    }

    #[test]
    pub fn cbc_padding_oracle() {
        let ct = gen_random_cbc_encryption();
        let mut discovered_bytes: Vec<u8> = vec![];
        let mut target_index = 16;
        while discovered_bytes.len() < 16 {
            target_index -= 1;
            let padding_value = 16 - target_index;
            let end_mask = xor(&discovered_bytes, &vec![padding_value]);
            // Find a good byte
            for candidate_byte in 0..=255 {
                let mut modified_ct = [
                    &ct[0..target_index as usize],
                    &[candidate_byte],
                    &end_mask,
                    &ct[16..32],
                ]
                .concat();
                assert!(modified_ct.len() == 32);
                let valid_padding = verify_padding(&modified_ct[0..32]);
                if valid_padding {
                    if padding_value == 1 {
                        // Make sure we aren't looking at a 2 byte padding
                        modified_ct[14] += 1;
                        if !verify_padding(&modified_ct[0..32]) {
                            continue;
                        }
                    }
                    discovered_bytes.insert(0, candidate_byte ^ padding_value);
                    break;
                }
                if candidate_byte == 255 {
                    panic!("didn't find anything");
                }
            }
        }
        dbg!(display(&xor(&discovered_bytes, &ct[0..16])));
    }
}
