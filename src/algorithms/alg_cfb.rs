use super::Kuznechik;
use crate::KeyStore;
use crate::types::{Block128, mut_cast_unchecked};
use crate::transforms::{sum_mod_2, addition_block_s_2, addition_rev_block_2, encrypt_block};
use std::convert::TryInto;

pub struct AlgCfb<'k> {
    kuz: &'k KeyStore,
    gamma: Vec<u8>,
    s: usize
}

impl<'k> Kuznechik<'k> for AlgCfb<'k> {
    fn new(kuz: &'k KeyStore) -> Self {
        AlgCfb { kuz, gamma: vec![], s: 16 }
    }

    fn set_gamma(&mut self, gamma: Vec<u8>) {
        self.gamma = gamma
    }

    fn encrypt(&mut self, mut data: Vec<u8>) -> Vec<u8> {
        if self.gamma.len() < 16 {
            panic!("Gamma length is less than 16 bytes");
        }

        addition_block_s_2(&mut data, self.s);

        let count_blocks = data.len() / self.s;
        for i in 0..count_blocks {
            let mut block : Block128 = self.gamma[..16].try_into().unwrap();
            encrypt_block(&mut block, &self.kuz.keys);

            let data_block: &mut Block128 = mut_cast_unchecked(&mut data[self.s*i..self.s*(i+1)]);

            // Ts transform
            sum_mod_2(data_block, &block);
            self.update_gamma(data_block);
        }

        data
    }

    fn decrypt(&mut self, mut data: Vec<u8>) -> Vec<u8> {
        if self.gamma.len() < 16 {
            panic!("Gamma length is less than 16 bytes");
        }

        let count_blocks = data.len() / self.s;
        for i in 0..count_blocks {
            let mut block : Block128 = self.gamma[..16].try_into().unwrap();
            encrypt_block(&mut block, &self.kuz.keys);

            let data_block: &mut Block128 = mut_cast_unchecked(&mut data[self.s*i..self.s*(i+1)]);

            self.update_gamma(&data_block[..]);
            // Ts transform
            sum_mod_2(data_block, &block);
        }

        addition_rev_block_2(&mut data);

        data
    }
}

impl<'k> AlgCfb<'k> {
    fn update_gamma(&mut self, data: &[u8]) {
        let len = self.gamma.len();
        assert!(len >= 16, "Gamma length is less than 16 bytes");
        assert!(data.len() >= self.s, "Data length is less than s bytes");

        let l = len - self.s;
        for i in 0..l {
            self.gamma[i] = self.gamma[i + self.s];
        }
        for i in 0..self.s {
            self.gamma[l+i] = data[i];
        }
    }
}
