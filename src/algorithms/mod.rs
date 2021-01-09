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
use crate::Kuznechik;

pub trait Algorithm<'k> {
    fn new(kuz: &'k Kuznechik) -> Self;
    fn encrypt(&mut self, data: Vec<u8>) -> Vec<u8>;
    fn decrypt(&mut self, data: Vec<u8>) -> Vec<u8>;
}
