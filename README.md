# Synchronous encryption algorithm "Kuznechik" (GOST R 34.12-2015, GOST R 34.13-2015)

Implementation of the block synchronous encryption algorithm "Kuznechik" in Rust lang.

## Encryption modes

| Struct |            Title            | Reduction |
|:------:|:--------------------------- |:---------:|
| AlgEcb | Electronic Codebook         |    ЕСВ    |
| AlgCtr | Counter                     |    CTR    |
| AlgOfb | Output Feedback             |    OFB    |
| AlgCbc | Cipher Block Chaining       |    СВС    |
| AlgCfb | Cipher Feedback             |    CFB    |
| AlgMac | Message Authentication Code |    MAC    |

## Usage (AlgOfb):
The following example encrypts and decrypts a 64-byte data block `data` using the OFB method. 
Encryption by other methods is similar, in some the gamma is not required 
(more details in [tests.rs](https://github.com/DmitryNX/Kuznechik/blob/master/src/tests.rs)).

```
extern crate kuznechik;

use self::kuznechik::{KeyStore, Kuznechik, AlgOfb};

fn main() {
    // Initialization
    let password = "Kuznechik";
    let data = Vec::from("Hello, World!");

    let gamma = vec![
        0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xce, 0xf0, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf0, 0x01, 0x12,
        0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x90, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
    ];

    let kuz = KeyStore::with_password(password);
    let mut cipher = AlgOfb::new(&kuz).gamma(gamma.clone());

    // Encryption
    let enc_data = cipher.encrypt(data.clone());

    // Decryption
    // Setting gamma again because OFB algorithm modify it during performing
    cipher.set_gamma(gamma);
    let dec_data = cipher.decrypt(enc_data);

    // Assert
    assert_eq!(data, dec_data);
}
```
