mod tests;

use std::convert::TryInto;
use crate::types::{Block128, Block256, mut_cast_unchecked};
use crate::tables::{K_PI, MULT_TABLE, K_PI_REV};

#[inline]
pub(crate) fn encrypt_block(data: &mut Block128, keys: &[Block128; 10]) {
    for i in 0..9 {
        tfm_lsx(data, &keys[i]);
    }
    tfm_x(data, &keys[9]);
}

#[inline]
pub(crate) fn decrypt_block(data: &mut Block128, keys: &[Block128; 10]) {
    for i in (1..=9).rev() {
        tfm_x(data, &keys[i]);
        tfm_rev_l(data);
        tfm_rev_s(data);
    }
    tfm_x(data, &keys[0]);
}

#[inline]
pub(crate) fn tfm_c(data: &mut Block128, number: u8) {
    *data = [0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,
        number];
    tfm_l(data);
}

#[inline]
pub(crate) fn tfm_f(data: &mut Block256, key: &Block128) {
    let temp: Block128 = data[..16].try_into().unwrap();

    let mut data_left = mut_cast_unchecked(&mut data[..16]);
    tfm_lsx(&mut data_left, &key);
    tfm_x_block256(data);
    data[16..].copy_from_slice(&temp);
}

#[inline]
fn tfm_lsx(data: &mut Block128, key: &Block128) {
    tfm_x(data, key);
    tfm_s(data);
    tfm_l(data);
}

#[inline]
fn tfm_x(data: &mut Block128, key: &Block128) {
    for i in 0..16 {
        data[i] ^= key[i];
    }
}

#[inline]
fn tfm_x_block256(data: &mut Block256) {
    for i in 0..16 {
        data[i] ^= data[i+16];
    }
}

/// В данном преобразовании используется подстановка π.
/// На вход поступает выходной параметр преобразования X и
/// его значение заменяется соответствующим значением из таблицы kPi.
#[inline]
fn tfm_s(data: &mut Block128) {
    for i in 0..16 {
        data[i] = K_PI[data[i] as usize];
    }
}

/// Преобразование L состоит в последовательной записи в старший разряд
/// результата R преобразования и сдвига влево на 1 символ.
/// Выполнив такой сдвиг 16 раз на выходе этого преобразования
/// будем иметь коэффициент распространения 17.
#[inline]
fn tfm_l(data: &mut Block128) {
    for _ in 0..16 {
        tfm_r(data);
    }
}

/// Конечное поле GF(2)[x]∕p(x), где p(x) = x8 + x7 + x6 + x + 1 ∈ GF(2)[x]
/// Определим линейное преобразование ℓ : V816 → V8 и сдвинем полученную
/// 16 байтную последовательность на 1 байт в сторону младшего разряда.
#[inline]
fn tfm_r(data: &mut Block128) {
    let temp = trf_linear(data);
    data.rotate_right(1);
    data[0] = temp;
}

#[inline]
fn trf_linear(data: &Block128) -> u8 {
    // indexes: 16, 32, 133, 148, 192, 194, 251
    let mut res = 0u8;
    res ^= MULT_TABLE[3][data[0] as usize];
    res ^= MULT_TABLE[1][data[1] as usize];
    res ^= MULT_TABLE[2][data[2] as usize];
    res ^= MULT_TABLE[0][data[3] as usize];
    res ^= MULT_TABLE[5][data[4] as usize];
    res ^= MULT_TABLE[4][data[5] as usize];
    res ^= data[6];
    res ^= MULT_TABLE[6][data[7] as usize];
    res ^= data[8];
    res ^= MULT_TABLE[4][data[9] as usize];
    res ^= MULT_TABLE[5][data[10] as usize];
    res ^= MULT_TABLE[0][data[11] as usize];
    res ^= MULT_TABLE[2][data[12] as usize];
    res ^= MULT_TABLE[1][data[13] as usize];
    res ^= MULT_TABLE[3][data[14] as usize];
    res ^= data[15];
    res
}

#[inline]
fn tfm_rev_s(data: &mut Block128) {
    for i in 0..16 {
        data[i] = K_PI_REV[data[i] as usize];
    }
}

/// Обратное преобразование R
#[inline]
fn tfm_rev_r(data: &mut Block128) {
    data.rotate_left(1);
    data[15] = trf_linear(data);
}

/// Обратное преобразование L
#[inline]
fn tfm_rev_l(data: &mut Block128) {
    for _ in 0..16 {
        tfm_rev_r(data);
    }
}

/// Побитовое сложение (по модулю 2)
/// Входные массивы b1 и b2 должны быть одинаковой длины,
/// либо b1.len() <= b2.len()
#[inline]
pub(crate) fn sum_mod_2(b1: &mut [u8], b2: &[u8]) {
    assert!(b1.len() <= b2.len());
    for i in 0..b1.len() {
        b1[i] ^= b2[i];
    }
}

#[inline]
pub(crate) fn addition_block128_2(data: &mut Vec<u8>) {
    addition_block_s_2(data, 16);
}

#[inline]
pub(crate) fn addition_block_s_2(data: &mut Vec<u8>, s: usize) {
    let len = data.len();
    let r = match len % s {
        0 => s,
        r => r
    };

    data.resize(len + r, 0);
    data[len] = 0x80;
}

#[inline]
pub(crate) fn addition_rev_block_2(data: &mut Vec<u8>) {
    let new_len = {
        match data.iter().rposition(|&x| x == 0x80) {
            Some(l) => l,
            None => data.len()
        }
    };

    data.resize(new_len, 0);
}
