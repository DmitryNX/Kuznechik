use super::{Block128, Block256, tables::*};
use std::convert::TryInto;
use crate::types::mut_cast_unchecked;

#[inline]
pub fn encrypt_block(data: &mut Block128, keys: &[Block128; 10]) {
    for i in 0..9 {
        tfm_lsx(data, &keys[i]);
    }
    tfm_x(data, &keys[9]);
}

#[inline]
pub fn decrypt_block(data: &mut Block128, keys: &[Block128; 10]) {
    for i in (1..=9).rev() {
        tfm_x(data, &keys[i]);
        tfm_rev_l(data);
        tfm_rev_s(data);
    }
    tfm_x(data, &keys[0]);
}

#[inline]
pub fn tfm_c(data: &mut Block128, number: u8) {
    *data = [0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,
        number];
    tfm_l(data);
}

#[inline]
pub fn tfm_f(data: &mut Block256, key: &Block128) {
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

/// Конечное поле GF(2)[x]∕p(x), где p(x) = x8 + x7 + x6 + x + 1 ∈ GF(2)[x]
/// Определим линейное преобразование ℓ : V816 → V8 и сдвинем полученную
/// 16 байтную последовательность на 1 байт в сторону младшего разряда.
#[inline]
fn tfm_r(data: &mut Block128) {
    let mut temp = 0u8;
    for i in 0..16 {
        temp ^= MULT_TABLE[(data[i] as usize * 256 + K_B[i] as usize) as usize];
    }

    data.rotate_right(1);
    data[0] = temp;
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
    let mut sum: u8 = 0;        // результат умножения в поле F
    for i in 0..16 {
        sum ^= MULT_TABLE[data[i] as usize * 256 + K_B[i] as usize];
    }
    data[15] = sum;
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
pub fn sum_mod_2(b1: &mut [u8], b2: &[u8]) {
    assert!(b1.len() <= b2.len());
    for i in 0..b1.len() {
        b1[i] ^= b2[i];
    }
}

#[inline]
pub fn addition_block128_2(data: &mut Vec<u8>) {
    addition_block_s_2(data, 16);
}

#[inline]
pub fn addition_block_s_2(data: &mut Vec<u8>, s: usize) {
    let len = data.len();
    let r = match len % s {
        0 => s,
        r => r
    };

    data.resize(len + r, 0);
    data[len] = 0x80;
}

#[inline]
pub fn addition_rev_block_2(data: &mut Vec<u8>) {
    let new_len = {
        match data.iter().rposition(|&x| x == 0x80) {
            Some(l) => l,
            None => data.len()
        }
    };

    data.resize(new_len, 0);
}


// ------------------------------------ TESTS ------------------------------------

#[test]
fn transform_s() {
    let mut data = [0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00];

    tfm_s(&mut data);
    assert_eq!(data, [0xb6, 0x6c, 0xd8, 0x88, 0x7d, 0x38, 0xe8, 0xd7, 0x77, 0x65, 0xae, 0xea, 0x0c, 0x9a, 0x7e, 0xfc]);

    tfm_s(&mut data);
    assert_eq!(data, [0x55, 0x9d, 0x8d, 0xd7, 0xbd, 0x06, 0xcb, 0xfe, 0x7e, 0x7b, 0x26, 0x25, 0x23, 0x28, 0x0d, 0x39]);

    tfm_s(&mut data);
    assert_eq!(data, [0x0c, 0x33, 0x22, 0xfe, 0xd5, 0x31, 0xe4, 0x63, 0x0d, 0x80, 0xef, 0x5c, 0x5a, 0x81, 0xc5, 0x0b]);

    tfm_s(&mut data);
    assert_eq!(data, [0x23, 0xae, 0x65, 0x63, 0x3f, 0x84, 0x2d, 0x29, 0xc5, 0xdf, 0x52, 0x9c, 0x13, 0xf5, 0xac, 0xda]);
}

#[test]
fn transform_r() {
    let mut data = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00];

    tfm_r(&mut data);
    assert_eq!(data, [0x94, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);

    tfm_r(&mut data);
    assert_eq!(data, [0xa5, 0x94, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

    tfm_r(&mut data);
    assert_eq!(data, [0x64, 0xa5, 0x94, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

    tfm_r(&mut data);
    assert_eq!(data, [0x0d, 0x64, 0xa5, 0x94, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
}

#[test]
fn transform_l() {
    let mut data = [0x64, 0xa5, 0x94, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

    tfm_l(&mut data);
    assert_eq!(data, [0xd4, 0x56, 0x58, 0x4d, 0xd0, 0xe3, 0xe8, 0x4c, 0xc3, 0x16, 0x6e, 0x4b, 0x7f, 0xa2, 0x89, 0x0d]);

    tfm_l(&mut data);
    assert_eq!(data, [0x79, 0xd2, 0x62, 0x21, 0xb8, 0x7b, 0x58, 0x4c, 0xd4, 0x2f, 0xbc, 0x4f, 0xfe, 0xa5, 0xde, 0x9a]);

    tfm_l(&mut data);
    assert_eq!(data, [0x0e, 0x93, 0x69, 0x1a, 0x0c, 0xfc, 0x60, 0x40, 0x8b, 0x7b, 0x68, 0xf6, 0x6b, 0x51, 0x3c, 0x13]);

    tfm_l(&mut data);
    assert_eq!(data, [0xe6, 0xa8, 0x09, 0x4f, 0xee, 0x0a, 0xa2, 0x04, 0xfd, 0x97, 0xbc, 0xb0, 0xb4, 0x4b, 0x85, 0x80]);
}
