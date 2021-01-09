use super::Algorithm;
use crate::Kuznechik;
use crate::types::Block128;
use crate::transforms::{sum_mod_2, encrypt_block};
use std::convert::TryInto;

pub struct AlgCtr<'k> {
    kuz: &'k Kuznechik,
    pub gamma: Vec<u8>
}

impl<'k> Algorithm<'k> for AlgCtr<'k> {
    fn new(kuz: &'k Kuznechik) -> Self {
        AlgCtr {
            kuz, gamma: vec![]
        }
    }

    fn encrypt(&mut self, mut data: Vec<u8>) -> Vec<u8> {
        let count_blocks = data.len() / 16;  // block128 len 16

        for i in 0..count_blocks {
            let mut block : Block128 = self.gamma[..16].try_into().unwrap();
            encrypt_block(&mut block, &self.kuz.keys,);
            sum_mod_2(&mut data[16*i..16*(i+1)], &block);
            add_ctr(&mut self.gamma);
        }

        let q_len = data.len() - count_blocks * 16;
        if q_len > 0 {
            let mut block : Block128 = self.gamma[..16].try_into().unwrap();
            encrypt_block(&mut block, &self.kuz.keys);
            sum_mod_2(&mut data[16*count_blocks..], &block[..]);
            add_ctr(&mut self.gamma);
        }
        data
    }

    fn decrypt(&mut self, data: Vec<u8>) -> Vec<u8> {
        self.encrypt(data)
    }
}

fn add_ctr(ctr: &mut Vec<u8>) {
    for i in (0..ctr.len()).rev() {
        ctr[i] += 1;
        if ctr[i] != 0 {
            break;
        }
    }
}
