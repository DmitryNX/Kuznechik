use super::Kuznechik;
use crate::KeyStore;
use crate::types::{Block128, mut_cast_unchecked};
use crate::transforms::{addition_block128_2, sum_mod_2, addition_rev_block_2, encrypt_block, decrypt_block};

pub struct AlgCbc<'k> {
    kuz: &'k KeyStore,
    gamma: Vec<u8>
}

impl<'k> Kuznechik<'k> for AlgCbc<'k> {
    fn new(kuz: &'k KeyStore) -> Self {
        AlgCbc {
            kuz, gamma: Vec::new()
        }
    }

    fn set_gamma(&mut self, gamma: Vec<u8>) {
        self.gamma = gamma
    }

    fn encrypt(&mut self, mut data: Vec<u8>) -> Vec<u8> {
        if self.gamma.len() < 16 {
            panic!("Gamma length is less than 16 bytes");
        }

        addition_block128_2(&mut data);

        let count_blocks = data.len() / 16;
        for i in 0..count_blocks {
            let data_block: &mut Block128 = mut_cast_unchecked(&mut data[16*i..16*(i+1)]);
            sum_mod_2(data_block, &self.gamma[..16]);

            encrypt_block(data_block, &self.kuz.keys);
            self.update_gamma(data_block);
        }

        data
    }

    fn decrypt(&mut self, mut data: Vec<u8>) -> Vec<u8> {
        if self.gamma.len() < 16 {
            panic!("Gamma length is less than 16 bytes");
        }

        let count_blocks = data.len() / 16;
        for i in 0..count_blocks {
            let data_block: &mut Block128 = mut_cast_unchecked(&mut data[16*i..16*(i+1)]);
            let data_block_c = data_block.clone();

            decrypt_block(data_block, &self.kuz.keys);
            sum_mod_2(data_block, &self.gamma[..16]);
            self.update_gamma(&data_block_c);
        }

        addition_rev_block_2(&mut data);
        data
    }
}

impl<'k> AlgCbc<'k> {
    fn update_gamma(&mut self, data: &Block128) {
        let len = self.gamma.len();
        assert!(len >= 16, "Gamma length is less than 16 bytes");

        let l = len-16;
        for i in 0..l {
            self.gamma[i] = self.gamma[l+i];
        }
        for i in 0..16 {
            self.gamma[l+i] = data[i];
        }

        // self.gamma[..len-16].copy_from_slice(&self.gamma[len-16..]);
        // self.gamma[len-16..].copy_from_slice(&data[..]);
    }
}
