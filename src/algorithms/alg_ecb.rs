use super::Kuznechik;
use crate::KeyStore;
use crate::types::mut_cast_unchecked;
use crate::transforms::{addition_block128_2, addition_rev_block_2, encrypt_block, decrypt_block};

pub struct AlgEcb<'k> {
    kuz: &'k KeyStore
}

impl<'k> Kuznechik<'k> for AlgEcb<'k> {
    fn new(kuz: &'k KeyStore) -> Self {
        AlgEcb { kuz }
    }

    fn set_gamma(&mut self, _gamma: Vec<u8>) { }

    fn encrypt(&mut self, mut data: Vec<u8>) -> Vec<u8> {
        addition_block128_2(&mut data);

        let count_blocks = data.len() / 16;

        for i in 0..count_blocks {
            encrypt_block(mut_cast_unchecked(&mut data[i*16 .. (i+1)*16]), &self.kuz.keys);
        }
        data
    }

    fn decrypt(&mut self, mut data: Vec<u8>) -> Vec<u8> {
        let count_blocks = data.len() / 16;

        for i in 0..count_blocks {
            decrypt_block(mut_cast_unchecked(&mut data[i*16 .. (i+1)*16]), &self.kuz.keys);
        }

        addition_rev_block_2(&mut data);
        data
    }
}
