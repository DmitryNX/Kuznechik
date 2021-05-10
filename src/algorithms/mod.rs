mod alg_ecb;
mod alg_ctr;
mod alg_ofb;
mod alg_cbc;
mod alg_cfb;
mod alg_mac;

pub use alg_ecb::AlgEcb;
pub use alg_ctr::AlgCtr;
pub use alg_ofb::AlgOfb;
pub use alg_cbc::AlgCbc;
pub use alg_cfb::AlgCfb;
pub use alg_mac::AlgMac;

use crate::KeyStore;
use crate::types::Block256;


///
/// # Synchronous encryption algorithm "Kuznechik" (GOST R 34.12-2015, GOST R 34.13-2015)
///
/// Implementation of the block synchronous encryption algorithm "Kuznechik" in Rust lang.
///
/// ## Encryption modes
///
/// | Struct |            Title            | Reduction |
/// |:------:|:--------------------------- |:---------:|
/// | AlgEcb | Electronic Codebook         |    ЕСВ    |
/// | AlgCtr | Counter                     |    CTR    |
/// | AlgOfb | Output Feedback             |    OFB    |
/// | AlgCbc | Cipher Block Chaining       |    СВС    |
/// | AlgCfb | Cipher Feedback             |    CFB    |
/// | AlgMac | Message Authentication Code |    MAC    |
///
/// ## Usage (AlgOfb):
/// The following example encrypts and decrypts a 64-byte data block `data` using the OFB method.
/// Encryption by other methods is similar, in some the gamma is not required
/// (more details in [tests.rs](https://github.com/DmitryNX/Kuznechik/blob/master/src/tests.rs)).
///
/// ```
/// extern crate kuznechik;
///
/// use self::kuznechik::{KeyStore, Kuznechik, AlgOfb};
///
/// fn main() {
///     let password = "Kuznechik";
///
///     let data = Vec::from("Hello, World!");
///
///     let gamma = vec![0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xce, 0xf0, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf0, 0x01, 0x12,
///                      0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x90, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19];
///
///     // Initialisation
///     let kuz = KeyStore::new().password(password);
///
///     let mut cipher = AlgOfb::new(&kuz).gamma(gamma.clone());
///
///     // Encryption
///     let enc_data = cipher.encrypt(data.clone());
///
///     // Decryption
///     cipher.set_gamma(gamma);
///     let dec_data = cipher.decrypt(enc_data);
///
///     assert_eq!(data, dec_data);
/// }
/// ```
///

pub trait Kuznechik<'k> : Sized {
    fn new(kuz: &'k KeyStore) -> Self;

    fn gamma(mut self, gamma: Vec<u8>) -> Self {
        self.set_gamma(gamma);
        self
    }

    fn set_gamma(&mut self, gamma: Vec<u8>);
    fn encrypt(&mut self, data: Vec<u8>) -> Vec<u8>;
    fn decrypt(&mut self, data: Vec<u8>) -> Vec<u8>;
}
