extern crate sha3;

mod types;
mod tables;
mod transforms;
mod algorithms;
mod tests;

use types::*;
use transforms::*;
pub use algorithms::*;
use std::convert::TryInto;

/**
# Алгоритм синхронного шифрования "Кузнечик" (ГОСТ Р 34.12-2015, ГОСТ Р 34.13-2015)<br>Synchronous encryption algorithm "Kuznechik" (GOST R 34.12-2015, GOST R 34.13-2015)

## Режимы шифрования / Encryption modes:
* AlgEcb - режим простой замены / Electronic Codebook (ЕСВ)
* AlgCtr - режим гаммирования / Counter (CTR)
* AlgOfb - режим гаммирования с обратной связью по выходу / Output Feedback (OFB)
* AlgCbc - режим простой замены с зацеплением / Cipher Block Chaining (СВС)
* AlgCfb - режим гаммирования с обратной связью по шифртексту / Cipher Feedback, (CFB)
* AlgMac - режим выработки имитовставки / Message Authentication Code (MAC)

# Использование / Usage (AlgOfb):
```
use self::kuznechik::{Kuznechik, Algorithm, AlgOfb};

// Инициализация / Initialization
let gamma = vec![0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xce, 0xf0, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf0, 0x01, 0x12,
                 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x90, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19];


let master_key = [0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                  0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];


let kuz = Kuznechik::new_with_master_key(master_key);
let mut alg = AlgOfb::new(&kuz);
alg.gamma = gamma.clone();


let data = vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xee, 0xff, 0x0a,
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xee, 0xff, 0x0a, 0x00,
                0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xee, 0xff, 0x0a, 0x00, 0x11];


// Шифрование / Encryption
let enc_data = alg.encrypt(data.clone());


assert_eq!(enc_data, vec![0x81, 0x80, 0x0a, 0x59, 0xb1, 0x84, 0x2b, 0x24, 0xff, 0x1f, 0x79, 0x5e, 0x89, 0x7a, 0xbd, 0x95,
                          0xed, 0x5b, 0x47, 0xa7, 0x04, 0x8c, 0xfa, 0xb4, 0x8f, 0xb5, 0x21, 0x36, 0x9d, 0x93, 0x26, 0xbf,
                          0x66, 0xa2, 0x57, 0xac, 0x3c, 0xa0, 0xb8, 0xb1, 0xc8, 0x0f, 0xe7, 0xfc, 0x10, 0x28, 0x8a, 0x13,
                          0x20, 0x3e, 0xbb, 0xc0, 0x66, 0x13, 0x86, 0x60, 0xa0, 0x29, 0x22, 0x43, 0xf6, 0x90, 0x31, 0x50]);


// Расшифрование / Decryption
alg.gamma = gamma;
let dec_data = alg.decrypt(enc_data);

assert_eq!(dec_data, data);
```
*/
pub struct Kuznechik {
    keys: [Block128; 10],
    master_key: Block256,
}

impl Kuznechik {
    pub fn new(password: &str) -> Result<Kuznechik, &'static str> {
        if password.len() < 4 {
            return Err("Password is very short");
        }
        let master_key = Self::hash_password(password);
        Ok(Self::new_with_master_key(master_key))
    }

    pub fn new_with_master_key(master_key: Block256) -> Kuznechik {
        let mut k = Kuznechik {
            keys: [[0u8; 16]; 10],
            master_key
        };
        k.expand_key();
        k
    }

    pub fn set_password(&mut self, password: &str) {
        self.master_key = Self::hash_password(password);
        self.expand_key();
    }

    fn hash_password(password: &str) -> Block256 {
        use sha3::{Digest, Sha3_256};

        let mut hasher = Sha3_256::new();
        hasher.update(password);

        hasher.finalize().as_slice().try_into()
            .expect("hash_password(): into Block256")
    }

    fn expand_key(&mut self) {
        let mut c: Block128 = [0u8; 16];
        let mut const_c: Block256 = self.master_key.clone();            // Iterative constants

        self.keys[0].copy_from_slice(&self.master_key[..16]);       // Key 1
        self.keys[1].copy_from_slice(&self.master_key[16..]);       // Key 2

        let mut k = 2;
        for j in 0..4 {
            for i in 1..9 {
                tfm_c(&mut c, j * 8 + i);
                tfm_f(&mut const_c, &c);
            }
            
            self.keys[k].copy_from_slice(&const_c[..16]);           // Key 3, 5, 7, 9
            k += 1;
            self.keys[k].copy_from_slice(&const_c[16..]);           // Key 4, 6, 8, 10
            k += 1;
        }
    }
}
