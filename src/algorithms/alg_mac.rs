use super::Kuznechik;
use crate::KeyStore;
use crate::types::Block128;
use crate::transforms::{sum_mod_2, encrypt_block};
use std::convert::TryInto;

pub struct AlgMac<'k> {
    kuz: &'k KeyStore,
    s: usize,
    k1: Block128,
    k2: Block128
}

impl<'k> Kuznechik<'k> for AlgMac<'k> {
    fn new(kuz: &'k KeyStore) -> Self {
        let mut a = AlgMac {
            kuz,
            s: 8,
            k1: [0u8; 16],
            k2: [0u8; 16]
        };
        a.make_k();
        a
    }

    fn set_gamma(&mut self, _gamma: Vec<u8>) { }

    fn encrypt(&mut self, mut data: Vec<u8>) -> Vec<u8> {
        let is_added = addition_block128_3(&mut data, 16);
        let count_blocks = data.len() / 16;

        let mut result: Block128 = data[..16].try_into().unwrap();
        encrypt_block(&mut result, &self.kuz.keys);

        for i in 1..count_blocks-1 {
            sum_mod_2(&mut result, &data[16*i..16*(i+1)]);
            encrypt_block(&mut result, &self.kuz.keys);
        }

        let key = match is_added {
            false => &self.k1,
            true => &self.k2
        };
        sum_mod_2(&mut result, &data[16*(count_blocks-1)..]);
        sum_mod_2(&mut result, key);
        encrypt_block(&mut result, &self.kuz.keys);

        result[..self.s].to_vec()
    }

    fn decrypt(&mut self, _data: Vec<u8>) -> Vec<u8> {
        panic!("AlmMac has not decrypt func");
    }
}

impl<'k> AlgMac<'k> {
    fn make_k(&mut self) {
        self.k1 = [0u8; 16];
        encrypt_block(&mut self.k1, &self.kuz.keys);
        mk_k(&mut self.k1);

        self.k2 = self.k1.clone();
        mk_k(&mut self.k2);
    }
}

fn mk_k(k: &mut Block128) {
    if shift_left(k) == 1 {
        k[15] ^= 0x87;
    };
}

fn shift_left(m: &mut [u8]) -> u8 {
    let len = m.len();
    let mut h = 0;
    let mut temp;
    for i in (0..len).rev() {
        temp = (m[i] >> 7) & 1;
        m[i] = (m[i] << 1) | h;
        h = temp;
    }
    h
}

fn addition_block128_3(data: &mut Vec<u8>, s: usize) -> bool {
    let r = data.len() % s;
    if r > 0 {
        let mut ex_data = Vec::<u8>::with_capacity(r);
        ex_data.push(0x80);
        for _ in 1..r {
            ex_data.push(0x00);
        }
        data.append(&mut ex_data);
        return true;
    }
    false
}
