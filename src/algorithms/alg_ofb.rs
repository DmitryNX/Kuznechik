use super::Kuznechik;
use crate::types::{Block128, mut_cast_unchecked};
use crate::transforms::{sum_mod_2, encrypt_block};
use std::convert::TryInto;
use crate::key_store::KeyStore;


pub struct AlgOfb<'k> {
    kuz: &'k KeyStore,
    gamma: Vec<u8>,
}

impl<'k> Kuznechik<'k> for AlgOfb<'k> {
    fn new(kuz: &'k KeyStore) -> Self {
        // let mut gamma = Vec::with_capacity(64);
        // assert!(gamma.len() >= 16);
        // gamma = vec![ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0f, 0x0e,
        //               0x10, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xf0, 0xe0 ];
        AlgOfb { kuz, gamma: vec![] }
    }

    fn set_gamma(&mut self, gamma: Vec<u8>) {
        self.gamma = gamma
    }

    fn encrypt(&mut self, mut data: Vec<u8>) -> Vec<u8> {
        let count_blocks = data.len() / 16;  // block128 len 16

        for i in 0..count_blocks {
            let mut block : &mut Block128 = mut_cast_unchecked(&mut self.gamma[..16]);
            encrypt_block(&mut block, &self.kuz.keys);
            sum_mod_2(&mut data[16*i..16*(i+1)], block);
            self.update_gamma();
        }

        let q_len = data.len() - count_blocks * 16;
        if q_len > 0 {
            let mut block : &mut Block128 = mut_cast_unchecked(&mut self.gamma[..16]);
            encrypt_block(&mut block, &self.kuz.keys);
            sum_mod_2(&mut data[16*count_blocks..], &block[..]);
            self.update_gamma();
        }

        data
    }

    fn decrypt(&mut self, data: Vec<u8>) -> Vec<u8> {
        self.encrypt(data)
    }
}

impl<'k> AlgOfb<'k> {
    fn update_gamma(&mut self) {
        let len = self.gamma.len();
        assert!(len >= 32, "Gamma length is less than 32");

        let temp: Block128 = self.gamma[..16].try_into().unwrap();
        for i in 16..len {
            let temp = self.gamma[i];
            self.gamma[i] = self.gamma[i - 16];
            self.gamma[i - 16] = temp;
        }
        self.gamma[len - 16..].copy_from_slice(&temp);
    }
}
