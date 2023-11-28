#![cfg(test)]

use crate::{KeyStore, Kuznechik, AlgOfb};


#[test]
fn encrypt_decrypt() {
    // Assign
    let password = "Kuznechik";
    let data = Vec::from("Hello, World!");

    let gamma = vec![
        0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xce, 0xf0, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf0, 0x01, 0x12,
        0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x90, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
    ];

    let kuz = KeyStore::with_password(password);

    let mut cipher = AlgOfb::new(&kuz).gamma(gamma.clone());

    // Act
    // Encryption
    let enc_data = cipher.encrypt(data.clone());

    // Decryption
    // Setting gamma again because OFB algorithm modify it during performing
    cipher.set_gamma(gamma);
    let dec_data = cipher.decrypt(enc_data);

    // Assert
    assert_eq!(data, dec_data);
}
