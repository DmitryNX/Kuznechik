#![cfg(test)]

use crate::KeyStore;
use super::{Kuznechik, AlgEcb, AlgCbc, AlgCfb, AlgCtr, AlgMac, AlgOfb};

const DATA: [u8; 64] = [
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xee, 0xff, 0x0a,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xee, 0xff, 0x0a, 0x00,
    0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xee, 0xff, 0x0a, 0x00, 0x11,
];

#[test]
fn encrypt_decrypt_alg_ecb() {
    // Assign
    let master_key = [
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    ];

    let kuz = KeyStore::with_master_key(master_key);
    let mut alg = AlgEcb::new(&kuz);

    let expected_enc_data = vec![
        0x7f, 0x67, 0x9d, 0x90, 0xbe, 0xbc, 0x24, 0x30, 0x5a, 0x46, 0x8d, 0x42, 0xb9, 0xd4, 0xed, 0xcd,
        0xb4, 0x29, 0x91, 0x2c, 0x6e, 0x00, 0x32, 0xf9, 0x28, 0x54, 0x52, 0xd7, 0x67, 0x18, 0xd0, 0x8b,
        0xf0, 0xca, 0x33, 0x54, 0x9d, 0x24, 0x7c, 0xee, 0xf3, 0xf5, 0xa5, 0x31, 0x3b, 0xd4, 0xb1, 0x57,
        0xd0, 0xb0, 0x9c, 0xcd, 0xe8, 0x30, 0xb9, 0xeb, 0x3a, 0x02, 0xc4, 0xc5, 0xaa, 0x8a, 0xda, 0x98,
    ];

    // Act
    let enc_data = alg.encrypt(DATA.to_vec());
    let dec_data = alg.decrypt(enc_data.clone());

    // Assert
    assert_eq!(
        enc_data[..64],
        expected_enc_data,
    );
    assert_eq!(dec_data, DATA);
}

#[test]
fn encrypt_decrypt_alg_ctr() {
    // Assign
    let gamma = vec![
        0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xce, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    let master_key = [
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    ];

    let expected_enc_data = vec![
        0xf1, 0x95, 0xd8, 0xbe, 0xc1, 0x0e, 0xd1, 0xdb, 0xd5, 0x7b, 0x5f, 0xa2, 0x40, 0xbd, 0xa1, 0xb8,
        0x85, 0xee, 0xe7, 0x33, 0xf6, 0xa1, 0x3e, 0x5d, 0xf3, 0x3c, 0xe4, 0xb3, 0x3c, 0x45, 0xde, 0xe4,
        0xa5, 0xea, 0xe8, 0x8b, 0xe6, 0x35, 0x6e, 0xd3, 0xd5, 0xe8, 0x77, 0xf1, 0x35, 0x64, 0xa3, 0xa5,
        0xcb, 0x91, 0xfa, 0xb1, 0xf2, 0x0c, 0xba, 0xb6, 0xd1, 0xc6, 0xd1, 0x58, 0x20, 0xbd, 0xba, 0x73,
    ];

    let kuz = KeyStore::with_master_key(master_key);
    let mut alg = AlgCtr::new(&kuz).gamma(gamma.clone());

    // Act
    let enc_data = alg.encrypt(DATA.to_vec());
    alg.set_gamma(gamma);
    let dec_data = alg.decrypt(enc_data.clone());

    // Assert
    assert_eq!(
        enc_data,
        expected_enc_data,
    );
    assert_eq!(dec_data, DATA);
}

#[test]
fn encrypt_decrypt_alg_ofb() {
    // Assign
    let gamma = vec![
        0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xce, 0xf0, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf0, 0x01, 0x12,
        0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x90, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
    ];

    let master_key = [
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    ];

    let expected_enc_data = vec![
        0x81, 0x80, 0x0a, 0x59, 0xb1, 0x84, 0x2b, 0x24, 0xff, 0x1f, 0x79, 0x5e, 0x89, 0x7a, 0xbd, 0x95,
        0xed, 0x5b, 0x47, 0xa7, 0x04, 0x8c, 0xfa, 0xb4, 0x8f, 0xb5, 0x21, 0x36, 0x9d, 0x93, 0x26, 0xbf,
        0x66, 0xa2, 0x57, 0xac, 0x3c, 0xa0, 0xb8, 0xb1, 0xc8, 0x0f, 0xe7, 0xfc, 0x10, 0x28, 0x8a, 0x13,
        0x20, 0x3e, 0xbb, 0xc0, 0x66, 0x13, 0x86, 0x60, 0xa0, 0x29, 0x22, 0x43, 0xf6, 0x90, 0x31, 0x50,
    ];

    let kuz = KeyStore::with_master_key(master_key);
    let mut alg = AlgOfb::new(&kuz).gamma(gamma.clone());

    // Act
    let enc_data = alg.encrypt(DATA.to_vec());
    alg.set_gamma(gamma);
    let dec_data = alg.decrypt(enc_data.clone());

    // Assert
    assert_eq!(
        enc_data,
        expected_enc_data,
    );
    assert_eq!(dec_data, DATA);
}

#[test]
fn encrypt_decrypt_alg_cbc() {
    // Assign
    let gamma = vec![
        0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xce, 0xf0, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf0, 0x01, 0x12,
        0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x90, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
    ];

    let master_key = [
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    ];

    let expected_enc_data = vec![
        0x68, 0x99, 0x72, 0xd4, 0xa0, 0x85, 0xfa, 0x4d, 0x90, 0xe5, 0x2e, 0x3d, 0x6d, 0x7d, 0xcc, 0x27,
        0x28, 0x26, 0xe6, 0x61, 0xb4, 0x78, 0xec, 0xa6, 0xaf, 0x1e, 0x8e, 0x44, 0x8d, 0x5e, 0xa5, 0xac,
        0xfe, 0x7b, 0xab, 0xf1, 0xe9, 0x19, 0x99, 0xe8, 0x56, 0x40, 0xe8, 0xb0, 0xf4, 0x9d, 0x90, 0xd0,
        0x16, 0x76, 0x88, 0x06, 0x5a, 0x89, 0x5c, 0x63, 0x1a, 0x2d, 0x9a, 0x15, 0x60, 0xb6, 0x39, 0x70,
    ];

    let kuz = KeyStore::with_master_key(master_key);
    let mut alg = AlgCbc::new(&kuz).gamma(gamma.clone());

    // Act
    let enc_data = alg.encrypt(DATA.to_vec());
    alg.set_gamma(gamma);
    let dec_data = alg.decrypt(enc_data.clone());

    // Assert
    assert_eq!(
        enc_data[..64],
        expected_enc_data,
    );
    assert_eq!(dec_data, DATA);
}

#[test]
fn encrypt_decrypt_alg_cfb() {
    // Assign
    let gamma = vec![
        0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xce, 0xf0, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf0, 0x01, 0x12,
        0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x90, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
    ];

    let master_key = [
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    ];

    let expected_enc_data = vec![
        0x81, 0x80, 0x0a, 0x59, 0xb1, 0x84, 0x2b, 0x24, 0xff, 0x1f, 0x79, 0x5e, 0x89, 0x7a, 0xbd, 0x95,
        0xed, 0x5b, 0x47, 0xa7, 0x04, 0x8c, 0xfa, 0xb4, 0x8f, 0xb5, 0x21, 0x36, 0x9d, 0x93, 0x26, 0xbf,
        0x79, 0xf2, 0xa8, 0xeb, 0x5c, 0xc6, 0x8d, 0x38, 0x84, 0x2d, 0x26, 0x4e, 0x97, 0xa2, 0x38, 0xb5,
        0x4f, 0xfe, 0xbe, 0xcd, 0x4e, 0x92, 0x2d, 0xe6, 0xc7, 0x5b, 0xd9, 0xdd, 0x44, 0xfb, 0xf4, 0xd1,
    ];

    let kuz = KeyStore::with_master_key(master_key);
    let mut alg = AlgCfb::new(&kuz).gamma(gamma.clone());

    // Act
    let enc_data = alg.encrypt(DATA.to_vec());
    alg.set_gamma(gamma);
    let dec_data = alg.decrypt(enc_data.clone());

    // Assert
    assert_eq!(
        enc_data[..64],
        expected_enc_data,
    );
    assert_eq!(dec_data, DATA);
}

#[test]
fn encrypt_decrypt_alg_mac() {
    // Assign
    let master_key = [
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    ];

    let expected_enc_data = vec![0x33, 0x6f, 0x4d, 0x29, 0x60, 0x59, 0xfb, 0xe3];

    let kuz = KeyStore::with_master_key(master_key);
    let mut alg = AlgMac::new(&kuz);

    // Act
    let enc_data = alg.encrypt(DATA.to_vec());

    // Assert
    assert_eq!(enc_data, expected_enc_data);
}
