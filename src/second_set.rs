#[cfg(test)]
mod second_set {
    use crate::{
        aes::{aes_decrypt, AESMode},
        utils::{display, read_base64_file},
    };

    #[test]
    pub fn implement_cbc_mode() {
        let ciphertext = read_base64_file("./10.txt");
        let key = b"YELLOW SUBMARINE";
        let decrypted = aes_decrypt(&ciphertext, AESMode::CBC, key);
        println!("Decrypted {:?}", display(&decrypted))
    }
}
